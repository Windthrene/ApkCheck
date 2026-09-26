<?php
/**
 * 检测接口（后端）
 *
 * GET  /api.php          返回服务端限制与权重表，供前端展示
 * POST /api.php          接收上传文件并检测
 *       表单字段：
 *         file       必填，上传的文件
 *         threshold  可选，及格线，默认 APKCHECK_DEFAULT_THRESHOLD
 *         detail     可选，传 1 时附带命中特征明细（会多算一次，略慢）
 *         maxSize    可选，体积上限（字节），默认不限
 *
 * 返回 JSON：
 *   {"ok":true,"name":"a.apk","size":117584379,"score":22,
 *    "threshold":7,"is_apk":true,"elapsed_ms":5.2,"memory_peak":"6 MB"}
 */

declare(strict_types=1);

require_once __DIR__ . '/apkcheck.php';

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

/**
 * @param array<string, mixed> $extra
 */
function respond(array $payload, int $status = 200): void
{
    http_response_code($status);
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

// ---------- GET：服务端能力信息 ----------
if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'GET') {
    respond([
        'ok'      => true,
        'version' => '1.0.0',
        'limits'  => api_limits() + [
            'memory_limit'       => ini_get('memory_limit'),
            'max_execution_time' => ini_get('max_execution_time'),
        ],
        'env' => [
            'php'      => PHP_VERSION,
            'zip_ext'  => class_exists('ZipArchive'),
            'zlib_ext' => function_exists('inflate_init'),
        ],
        'default_threshold' => APKCHECK_DEFAULT_THRESHOLD,
        'strict_threshold'  => APKCHECK_STRICT_THRESHOLD,
        'weights'           => apkcheck_default_weights(),
        'weight_labels'     => array_map(
            static fn(string $k): string => apkcheck_feature_label($k),
            array_keys(apkcheck_default_weights())
        ),
    ]);
}

/**
 * 把 php.ini 里的 256M / 1G 这类值换算成字节
 */
function api_ini_to_bytes(string $value): int
{
    $value = strtolower(trim($value));
    if ($value === '') {
        return 0;
    }
    $num  = (int)$value;
    $unit = substr($value, -1);
    return match ($unit) {
        'g'     => $num * 1073741824,
        'm'     => $num * 1048576,
        'k'     => $num * 1024,
        default => $num,
    };
}

function api_limits(): array
{
    return [
        'upload_max_filesize' => (string)ini_get('upload_max_filesize'),
        'post_max_size'       => (string)ini_get('post_max_size'),
        'upload_max_bytes'    => api_ini_to_bytes((string)ini_get('upload_max_filesize')),
        'post_max_bytes'      => api_ini_to_bytes((string)ini_get('post_max_size')),
    ];
}

// ---------- POST：检测上传文件 ----------
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond(['ok' => false, 'error' => '仅支持 GET / POST'], 405);
}

/*
 * 关键：文件超过 post_max_size 时，PHP 会把整个请求体（$_POST 和 $_FILES 一起）静默丢弃，
 * 此时看起来就像"没有 file 字段"。这里先按 CONTENT_LENGTH 判断，给出准确原因。
 */
$contentLen = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
$limits     = api_limits();

if ($contentLen > 0 && $limits['post_max_bytes'] > 0 && $contentLen > $limits['post_max_bytes']) {
    respond([
        'ok'     => false,
        'code'   => 'POST_TOO_LARGE',
        'error'  => '请求体积 ' . apkcheck_hsize($contentLen) . ' 超过服务器 post_max_size（'
                    . $limits['post_max_size'] . '），PHP 已丢弃整个请求。'
                    . '请调大 php.ini 的 post_max_size / upload_max_filesize 后重试。',
        'limits' => $limits,
    ], 413);
}

if (empty($_POST) && empty($_FILES)) {
    respond([
        'ok'     => false,
        'code'   => 'EMPTY_BODY',
        'error'  => '没有收到任何表单数据。常见原因：文件超过 upload_max_filesize / post_max_size '
                    . '被服务器丢弃，或请求不是 multipart/form-data。',
        'limits' => $limits,
    ], 400);
}

$threshold = isset($_POST['threshold']) && $_POST['threshold'] !== ''
    ? (int)$_POST['threshold']
    : APKCHECK_DEFAULT_THRESHOLD;
$wantDetail = !empty($_POST['detail']);
$opts       = ['threshold' => $threshold];

if (isset($_POST['maxSize']) && is_numeric($_POST['maxSize'])) {
    $opts['maxSize'] = (int)$_POST['maxSize'];
}

if (empty($_FILES['file'])) {
    respond([
        'ok'     => false,
        'code'   => 'NO_FILE_FIELD',
        'error'  => '没有收到名为 file 的上传字段（收到的字段：'
                    . (empty($_FILES) ? '无' : implode(', ', array_keys($_FILES))) . '）',
        'limits' => $limits,
    ], 400);
}

$f = $_FILES['file'];

// 多个文件的情况（name="file[]"）只取第一个，前端是逐个上传的
if (is_array($f['error'])) {
    $f = [
        'name'     => $f['name'][0] ?? '',
        'type'     => $f['type'][0] ?? '',
        'tmp_name' => $f['tmp_name'][0] ?? '',
        'error'    => $f['error'][0] ?? UPLOAD_ERR_NO_FILE,
        'size'     => $f['size'][0] ?? 0,
    ];
}

$uploadErrors = [
    UPLOAD_ERR_INI_SIZE   => '文件超过服务器上传限制（upload_max_filesize）',
    UPLOAD_ERR_FORM_SIZE  => '文件超过表单声明的体积上限',
    UPLOAD_ERR_PARTIAL    => '文件只有部分被上传，请重试',
    UPLOAD_ERR_NO_FILE    => '没有文件被上传',
    UPLOAD_ERR_NO_TMP_DIR => '服务器缺少临时目录',
    UPLOAD_ERR_CANT_WRITE => '服务器写入临时文件失败',
    UPLOAD_ERR_EXTENSION  => '上传被扩展拦截',
];

if ((int)$f['error'] !== UPLOAD_ERR_OK) {
    respond([
        'ok'     => false,
        'code'   => 'UPLOAD_ERR_' . (int)$f['error'],
        'error'  => $uploadErrors[(int)$f['error']] ?? ('上传失败，错误码 ' . (int)$f['error']),
        'limits' => $limits,
    ], 400);
}

$tmp = (string)$f['tmp_name'];
if ($tmp === '' || !is_uploaded_file($tmp)) {
    respond(['ok' => false, 'error' => '非法上传文件'], 400);
}

// 直接在临时文件上检测，不落盘、不留副本
$m0      = memory_get_usage(true);
$t0      = microtime(true);
$score   = apkcheck_score($tmp, $opts);           // 只取分值
$ms      = round((microtime(true) - $t0) * 1000, 1);
$memUsed = memory_get_peak_usage(true) - $m0;

$out = [
    'ok'               => true,
    'name'             => basename((string)$f['name']),
    'size'             => (int)$f['size'],
    'size_human'       => apkcheck_hsize((int)$f['size']),
    'score'            => $score,
    'threshold'        => $threshold,
    'is_apk'           => $score >= $threshold,
    'elapsed_ms'       => $ms,
    // delta：本次检测新增的内存；peak：整个请求的真实内存峰值（含 PHP 基线）
    'memory_used'      => apkcheck_hsize($memUsed),
    'memory_used_byte' => $memUsed,
    'memory_peak'      => apkcheck_hsize(memory_get_peak_usage(true)),
    'memory_peak_byte' => memory_get_peak_usage(true),
];

if ($wantDetail) {
    $v = apkcheck_verify($tmp, $opts + ['entries' => false]);
    $out['detail'] = [
        'level'       => $v['level'],
        'level_label' => apkcheck_level_label($v['level']),
        'code'        => $v['code'],
        'message'     => $v['message'],
        'entry_count' => $v['entry_count'],
        'features'    => $v['features'],
        'warnings'    => $v['warnings'],
    ];
}

respond($out);
