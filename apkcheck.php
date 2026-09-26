<?php
/**
 * APK 文件检测工具（积分制判定 · 单文件零依赖）
 *
 * 主入口只有一个函数：
 *
 *     $score = apkcheck_score('/path/to/app.apk');   // 只返回整数分值，不做任何输出
 *     if ($score >= 7) { /* 是 APK *\/ }
 *
 * 判定方式：每命中一个 APK 特征就累加对应分值（内容校验不过还会扣分），
 * 总分 >= 门槛即判定为 APK。只含 classes.dex、或只含 resources.arsc 的包都能通过，
 * 普通 ZIP 压缩包因命中特征太少会被拒绝。
 *
 * 需要诊断信息（命中了哪些特征、为什么被拒）时用 apkcheck_verify()，
 * 它返回完整数组；apkcheck_score() 只是它的一个「只取分值」的薄封装。
 *
 * ── 性能设计（面向 1 核 1G 这类低配服务器）──────────────────────────
 *   1. 只读文件头 4 字节判断容器，绝不把整包读进内存
 *   2. 只读文件尾部定位 EOCD，直接拿到条目总数 / 中央目录偏移，不遍历条目
 *   3. 特征匹配采用「中央目录字节流 strpos」：C 级别的字符串搜索，
 *      不构建 PHP 数组、不解压任何条目，内存占用与包体大小无关
 *   4. 内容校验（AXML / dex / arsc 魔数）只对 3 个目标条目各读 8 字节，
 *      deflate 条目走增量解压，最多读 64KB
 *   5. 不使用 ZipArchive 建立索引（它在万级条目上要几百毫秒），
 *      只在自研读取器失败时才回退
 *   6. 中央目录超过 8MB 时分块扫描，支持提前收工与超时中止
 *
 * 检测流程：
 *   1. 文件存在性 / 可读性 / 体积区间（可选，默认不限体积）
 *   2. ZIP 容器魔数（硬性前置：PK\x03\x04 / PK\x05\x06 / PK\x07\x08）
 *   3. 解析 EOCD + 扫描中央目录字节流，命中特征加分
 *   4. 读取 AndroidManifest.xml / classes.dex / resources.arsc 的头部做内容校验，
 *      通过加分，不通过扣分（识别伪造包的主要手段）
 *   5. 累加得到总分
 *
 * PHP >= 7.4，推荐 8.x。zip / zlib 扩展缺失时自动降级（跳过内容校验），仍能工作。
 */

declare(strict_types=1);

if (!defined('APKCHECK_MIN_SIZE')) {
    /** 最小体积阈值（字节），仅用于排除空文件 / 垃圾文件，不参与积分 */
    define('APKCHECK_MIN_SIZE', 128);
}

if (!defined('APKCHECK_MAX_SIZE')) {
    /**
     * 默认最大可检测体积，0 = 不限制。
     *
     * 库本身不设业务上限：上传体积该由 php.ini / nginx 管（你的场景是 256MB），
     * 需要自我保护时再显式传 options['maxSize']，例如 256 * 1024 * 1024。
     */
    define('APKCHECK_MAX_SIZE', 0);
}

if (!defined('APKCHECK_DEFAULT_THRESHOLD')) {
    /** 默认及格线：manifest(4) + AXML 校验(2) 之后再命中 1 分特征即可 */
    define('APKCHECK_DEFAULT_THRESHOLD', 7);
}

if (!defined('APKCHECK_STRICT_THRESHOLD')) {
    /** 严格门槛：要求 manifest 之外还有 dex 或 arsc 这类强特征 */
    define('APKCHECK_STRICT_THRESHOLD', 10);
}

if (!defined('APKCHECK_MAX_CD_SCAN')) {
    /** 中央目录单次读入的最大字节数，超过则分块扫描（控制内存峰值） */
    define('APKCHECK_MAX_CD_SCAN', 8 * 1024 * 1024);
}

if (!defined('APKCHECK_CD_CHUNK')) {
    /** 分块扫描时每块的字节数 */
    define('APKCHECK_CD_CHUNK', 2 * 1024 * 1024);
}

/**
 * 默认特征权重表
 *
 * 正值 = 命中加分，负值 = 内容校验不通过时扣分（用于识别伪造特征）。
 * 可用 options['weights'] 整体或局部覆盖，例如 ['dex' => 5]。
 *
 * @return array<string, int>
 */
function apkcheck_default_weights(): array
{
    return [
        // —— 加分项 ——
        'manifest'      => 4,   // AndroidManifest.xml，APK 最核心的身份特征
        'manifest_axml' => 2,   // manifest 头部是合法 Android 二进制 XML
        'dex'           => 3,   // classes.dex / classes2.dex ...
        'dex_magic'     => 1,   // classes.dex 头部是合法 dex 魔数
        'arsc'          => 3,   // resources.arsc 编译后的资源表
        'arsc_magic'    => 1,   // resources.arsc 头部是合法资源表
        'res_dir'       => 2,   // res/ 资源目录
        'native_lib'    => 2,   // lib/<abi>/*.so 原生库
        'signature'     => 2,   // META-INF/*.SF|RSA|DSA|EC 签名块
        'dex_hidden'    => 2,   // dex 藏在 assets/ 或 lib/ 下（加固加壳特征）
        'jar_meta'      => 1,   // META-INF/MANIFEST.MF
        'assets'        => 1,   // assets/ 资源目录
        // —— 扣分项 ——
        'manifest_bad'  => -4,  // 有 AndroidManifest.xml 但内容不是 AXML（改名伪造）
        'dex_bad'       => -3,  // 有 classes.dex 但内容不是 dex
        'arsc_bad'      => -3,  // 有 resources.arsc 但内容不是资源表
        'nested_apk'    => -2,  // 自身无 manifest，包内却还有 .apk（.apks/.xapk 集合包）
    ];
}

/**
 * 特征键的中文说明
 */
function apkcheck_feature_label(string $key): string
{
    return [
        'manifest'      => 'AndroidManifest.xml',
        'manifest_axml' => 'Manifest 合法 AXML',
        'manifest_bad'  => 'Manifest 非 AXML',
        'dex'           => 'classes.dex',
        'dex_magic'     => 'dex 魔数正确',
        'dex_bad'       => 'dex 内容非法',
        'arsc'          => 'resources.arsc',
        'arsc_magic'    => 'arsc 魔数正确',
        'arsc_bad'      => 'arsc 内容非法',
        'res_dir'       => 'res/ 目录',
        'native_lib'    => 'lib/ 原生库',
        'signature'     => 'META-INF 签名',
        'dex_hidden'    => 'dex 藏于 assets/lib',
        'jar_meta'      => 'META-INF/MANIFEST.MF',
        'assets'        => 'assets/ 目录',
        'nested_apk'    => '包内嵌 .apk（集合包）',
    ][$key] ?? $key;
}

/**
 * 检测一个文件是否为 APK（积分制）
 *
 * @param string $filePath 待检测文件的绝对或相对路径
 * @param array  $options  可选配置：
 *                         - threshold int     及格线，默认 APKCHECK_DEFAULT_THRESHOLD（7）
 *                         - weights   array   特征权重覆盖，默认 apkcheck_default_weights()
 *                         - maxSize   int     体积上限，默认 APKCHECK_MAX_SIZE（256MB）
 *                         - minSize   int     体积下限，默认 APKCHECK_MIN_SIZE（128）
 *                         - content   bool    是否读取条目头部做内容校验（默认 true，需 zip 扩展）
 *                         - deep      bool    硬校验：内容校验不通过直接判否，而不是扣分（默认 false）
 *                         - timeout   float   扫描超时秒数，0 表示不限（默认 0）
 *                         - entries   bool    是否在结果里返回完整条目列表（默认 false，省内存）
 *                         - strict    bool    兼容旧参数：true 等价于 threshold=10
 *
 * @return array{
 *     is_apk: bool,
 *     level: string,
 *     code: string,
 *     message: string,
 *     score: int,
 *     threshold: int,
 *     features: array<int, array{key: string, points: int, label: string}>,
 *     warnings: string[],
 *     path: string,
 *     size: int,
 *     entry_count: int,
 *     entries: string[]|null,
 *     detail: array<string, mixed>
 * }
 *
 * @see apkcheck_level_label()     level 字段中文说明
 * @see apkcheck_default_weights() 特征权重表
 */
function apkcheck_verify(string $filePath, array $options = []): array
{
    $started = microtime(true);

    if (isset($options['threshold']) && is_numeric($options['threshold'])) {
        $threshold = (int)$options['threshold'];
    } elseif (!empty($options['strict']) && $options['strict'] !== 'warn') {
        $threshold = APKCHECK_STRICT_THRESHOLD;
    } else {
        $threshold = APKCHECK_DEFAULT_THRESHOLD;
    }

    $weights   = array_replace(apkcheck_default_weights(), $options['weights'] ?? []);
    $maxSize   = (int)($options['maxSize'] ?? APKCHECK_MAX_SIZE);
    $minSize   = (int)($options['minSize'] ?? APKCHECK_MIN_SIZE);
    $wantEntryList = (bool)($options['entries'] ?? false);
    $timeout   = (float)($options['timeout'] ?? 0);
    $deep      = (bool)($options['deep'] ?? false);
    // 内容校验默认开启；deep 模式强制开启
    $doContent = $deep || (bool)($options['content'] ?? true);

    $result = [
        'is_apk'      => false,
        'level'       => 'invalid',
        'code'        => 'UNKNOWN',
        'message'     => '',
        'score'       => 0,
        'threshold'   => $threshold,
        'features'    => [],
        'warnings'    => [],
        'path'        => $filePath,
        'size'        => 0,
        'entry_count' => 0,
        'entries'     => null,
        'detail'      => [],
    ];

    $fail = static function (string $code, string $message, array $detail = []) use (&$result): array {
        $result['code']    = $code;
        $result['message'] = $message;
        $result['detail']  = $detail;
        $result['level']   = match ($code) {
            'NOT_ZIP'                       => 'not_zip',
            'ZIP_BROKEN', 'BAD_MANIFEST',
            'BAD_DEX', 'BAD_ARSC'           => 'broken_zip',
            'NO_MANIFEST', 'SCORE_LOW'      => 'plain_zip',
            default                         => 'invalid',
        };
        return $result;
    };

    // ---------- 1. 基础校验（硬性前置，全部是廉价系统调用） ----------
    if ($filePath === '' || trim($filePath) === '') {
        return $fail('EMPTY_PATH', '文件路径为空');
    }
    if (!file_exists($filePath)) {
        return $fail('NOT_FOUND', '文件不存在：' . $filePath);
    }
    if (is_dir($filePath)) {
        return $fail('IS_DIR', '给定路径是目录，不是文件：' . $filePath);
    }
    if (!is_readable($filePath)) {
        return $fail('NOT_READABLE', '文件不可读（权限不足）：' . $filePath);
    }

    $size = @filesize($filePath);
    if ($size === false) {
        return $fail('SIZE_ERROR', '无法获取文件大小');
    }
    $result['size'] = $size;

    if ($size < $minSize) {
        return $fail('TOO_SMALL', '文件过小（' . $size . ' 字节），不可能是 APK', ['min' => $minSize]);
    }
    if ($maxSize > 0 && $size > $maxSize) {
        return $fail(
            'TOO_LARGE',
            '文件超过体积上限（' . apkcheck_hsize($size) . ' > ' . apkcheck_hsize($maxSize) . '），已跳过检测',
            ['max' => $maxSize]
        );
    }

    // ---------- 2. ZIP 魔数校验（只读 4 字节） ----------
    $fp = @fopen($filePath, 'rb');
    if ($fp === false) {
        return $fail('OPEN_FAILED', '无法打开文件进行读取');
    }

    $magic = fread($fp, 4);
    if ($magic === false || strlen($magic) < 4) {
        fclose($fp);
        return $fail('OPEN_FAILED', '文件内容不足 4 字节，无法识别');
    }

    $zipSignatures = [
        "\x50\x4B\x03\x04" => 'local_file_header',
        "\x50\x4B\x05\x06" => 'end_of_central_dir',
        "\x50\x4B\x07\x08" => 'spanned_archive',
    ];
    $magicLabel = $zipSignatures[$magic] ?? null;
    if ($magicLabel === null) {
        fclose($fp);
        $hint = apkcheck_guess_type_by_magic($magic);
        return $fail(
            'NOT_ZIP',
            '文件头不是 ZIP 格式' . ($hint !== '' ? '（看起来像是 ' . $hint . '）' : ''),
            ['magic_hex' => bin2hex($magic)]
        );
    }
    $result['detail']['container'] = 'zip:' . $magicLabel;

    // ---------- 3. 解析 EOCD：拿到条目数与中央目录位置（不遍历条目） ----------
    $eocd = apkcheck_read_eocd($fp, $size);
    if ($eocd === null) {
        fclose($fp);
        return $fail('ZIP_BROKEN', '文件头是 ZIP，但找不到结束记录（EOCD），文件可能已损坏或被截断');
    }
    $result['entry_count'] = $eocd['entry_count'];
    $result['detail']['cd_size'] = $eocd['cd_size'];

    // ---------- 4. 扫描中央目录字节流匹配特征 ----------
    $scan = apkcheck_scan_central_dir(
        $fp,
        $eocd['cd_offset'],
        $eocd['cd_size'],
        $timeout > 0 ? $started + $timeout : 0.0
    );

    if ($scan === null) {
        fclose($fp);
        return $fail('TIMEOUT', '扫描中央目录超时，已中止检测');
    }
    if ($scan['truncated']) {
        $result['warnings'][] = '中央目录过大，只扫描了前 ' . apkcheck_hsize($scan['scanned']) . '，特征可能统计不全';
    }

    // ---------- 5. 内容校验：只读取 3 个条目的前 8 字节 ----------
    // 优先走自研读取器（不加载 libzip、不建索引）；失败才回退 ZipArchive
    $contentOk = ['manifest' => null, 'dex' => null, 'arsc' => null];   // null=未校验
    $heads     = [];
    if ($doContent) {
        foreach (['manifest' => 'AndroidManifest.xml', 'dex' => 'classes.dex', 'arsc' => 'resources.arsc'] as $key => $entryName) {
            if (!$scan['hits'][$key] || $scan['hdr'][$key] === null) {
                continue;
            }
            $data = apkcheck_read_entry_head_native($fp, $scan['hdr'][$key], 8);
            if ($data === null) {
                continue;   // 交给下面的 ZipArchive 兜底
            }
            $heads[$entryName] = $data;
        }
    }

    $missing = [];
    foreach (['manifest' => 'AndroidManifest.xml', 'dex' => 'classes.dex', 'arsc' => 'resources.arsc'] as $key => $entryName) {
        if ($doContent && $scan['hits'][$key] && !isset($heads[$entryName])) {
            $missing[] = $entryName;
        }
    }

    // 需要返回完整条目列表 / 兜底读取：才动用 libzip
    if ($wantEntryList || ($missing !== [] && class_exists('ZipArchive'))) {
        if ($wantEntryList) {
            $result['entries'] = class_exists('ZipArchive')
                ? apkcheck_list_entries_by_ziparchive($filePath)
                : apkcheck_list_entries_manual($filePath);
        }
        if ($missing !== []) {
            foreach (apkcheck_read_entry_heads($filePath, $missing, 8) as $name => $data) {
                $heads[$name] = $data;
            }
        }
    }
    fclose($fp);

    if (isset($heads['AndroidManifest.xml'])) {
        $contentOk['manifest'] = apkcheck_is_axml($heads['AndroidManifest.xml']);
    }
    if (isset($heads['classes.dex'])) {
        $contentOk['dex'] = apkcheck_is_dex($heads['classes.dex']);
    }
    if (isset($heads['resources.arsc'])) {
        $contentOk['arsc'] = apkcheck_is_arsc($heads['resources.arsc']);
    }

    $needContent = $scan['hits']['manifest'] || $scan['hits']['dex'] || $scan['hits']['arsc'];
    $canRead     = $contentOk['manifest'] !== null || $contentOk['dex'] !== null || $contentOk['arsc'] !== null;
    if ($doContent && $needContent && !$canRead) {
        $result['warnings'][] = '内容校验未完成（条目定位失败或 zip/zlib 扩展缺失），少 3~4 分，建议把门槛下调 3 分';
    }

    // 硬校验模式：内容不对直接判否（null=没能校验，不参与硬判定）
    if ($deep) {
        if ($contentOk['manifest'] === false) {
            return $fail('BAD_MANIFEST', '硬校验失败：AndroidManifest.xml 不是合法的 Android 二进制 XML');
        }
        if ($contentOk['dex'] === false) {
            return $fail('BAD_DEX', '硬校验失败：classes.dex 内容不是合法的 dex 文件');
        }
        if ($contentOk['arsc'] === false) {
            return $fail('BAD_ARSC', '硬校验失败：resources.arsc 内容不是合法的资源表');
        }
    }

    // ---------- 6. 计算积分 ----------
    $features = [];
    $score    = 0;
    $add      = static function (string $key) use (&$features, &$score, $weights): void {
        $points     = (int)($weights[$key] ?? 0);
        $score     += $points;
        $features[] = ['key' => $key, 'points' => $points, 'label' => apkcheck_feature_label($key)];
    };

    $hits = $scan['hits'];

    // manifest：命中则加分；内容校验通过再加分，校验不通过改为倒扣
    if ($hits['manifest']) {
        if ($contentOk['manifest'] === false) {
            $add('manifest_bad');
        } else {
            $add('manifest');
            if ($contentOk['manifest'] === true) {
                $add('manifest_axml');
            }
        }
    }

    // classes.dex
    if ($hits['dex']) {
        if ($contentOk['dex'] === false) {
            $add('dex_bad');
        } else {
            $add('dex');
            if ($contentOk['dex'] === true) {
                $add('dex_magic');
            }
        }
    }

    // resources.arsc
    if ($hits['arsc']) {
        if ($contentOk['arsc'] === false) {
            $add('arsc_bad');
        } else {
            $add('arsc');
            if ($contentOk['arsc'] === true) {
                $add('arsc_magic');
            }
        }
    }

    // 纯目录 / 元数据类特征
    if ($hits['res_dir']) {
        $add('res_dir');
    }
    if ($hits['native_lib']) {
        $add('native_lib');
    }
    if ($hits['signature']) {
        $add('signature');
    }
    if ($hits['jar_meta']) {
        $add('jar_meta');
    }
    if ($hits['assets']) {
        $add('assets');
    }

    // dex 不在根目录但 assets/ 或 lib/ 下有 .dex/.jar：加壳特征
    if (!$hits['dex'] && $hits['dex_ext'] && ($hits['assets'] || $hits['native_lib'])) {
        $add('dex_hidden');
    }

    // 自身没有 manifest，包内却还有 .apk：这是 .apks/.xapk 集合包
    if (!$hits['manifest'] && $hits['apk_ext']) {
        $add('nested_apk');
    }

    usort($features, static fn(array $a, array $b): int => $b['points'] <=> $a['points']);

    $result['score']    = $score;
    $result['features'] = $features;
    $result['detail']['hits'] = implode(',', array_keys(array_filter($hits)));
    $result['detail']['content_checked'] = $contentOk['manifest'] !== null
        || $contentOk['dex'] !== null
        || $contentOk['arsc'] !== null;
    $result['detail']['elapsed_ms'] = (int)round((microtime(true) - $started) * 1000);

    $hasManifest = $hits['manifest'] && $contentOk['manifest'] !== false;
    $hasDex      = $hits['dex'] && $contentOk['dex'] !== false;
    $hasArsc     = $hits['arsc'] && $contentOk['arsc'] !== false;

    // 结构分级（与积分无关，纯结构描述）
    if ($hasManifest) {
        $result['level'] = ($hasDex || $hasArsc) ? 'apk_complete' : 'apk_manifest_only';
    }

    if ($hasManifest) {
        foreach (apkcheck_describe_structure($hits, $contentOk) as $w) {
            $result['warnings'][] = $w;
        }
    }

    // ---------- 7. 积分判定 ----------
    if ($score < $threshold) {
        if (!$hits['manifest']) {
            return $fail(
                'NO_MANIFEST',
                '缺少 AndroidManifest.xml，积分 ' . $score . ' < 门槛 ' . $threshold . '：这是普通 ZIP 压缩包'
            );
        }
        $out = $fail(
            'SCORE_LOW',
            '积分不足：' . $score . ' < 门槛 ' . $threshold . '（命中：' . ($result['detail']['hits'] ?: '无') . '）'
        );
        $out['level'] = $hits['manifest'] ? 'apk_manifest_only' : 'plain_zip';
        return $out;
    }

    $result['is_apk']  = true;
    $result['code']    = 'OK';
    $result['message'] = '是 APK（积分 ' . $score . ' >= 门槛 ' . $threshold . '）';

    if ($score < $threshold + 2) {
        $result['warnings'][] = '积分刚过门槛（' . $score . '/' . $threshold . '），命中特征偏少，建议人工复核';
    }

    return $result;
}

/**
 * 检测一个文件像不像 APK，只返回分值
 *
 * 这是本库的主入口：不 echo、不写文件、不抛异常，只给出一个整数。
 * 判定交给调用方：分数 >= 门槛（默认 7）即认为是 APK。
 *
 * 任何异常输入（文件不存在、不是 ZIP、结构损坏、伪造特征）都不会报错，
 * 而是体现在分值上——不存在 / 损坏得 0 分，伪造特征会倒扣成负分。
 *
 * @param string $filePath 待检测文件路径
 * @param array  $options  见 apkcheck_verify()（threshold 在这里不起作用，分数与门槛无关）
 * @return int 分值；完全不像 APK 时返回 0 或负数
 */
function apkcheck_score(string $filePath, array $options = []): int
{
    return (int)apkcheck_verify($filePath, $options)['score'];
}

/**
 * 判断检测结果是否通过（便捷封装，用默认门槛）
 */
function apkcheck_is_apk(string $filePath, array $options = []): bool
{
    return apkcheck_verify($filePath, $options)['is_apk'];
}

/**
 * 读取 ZIP 结束记录（EOCD），拿到条目数与中央目录位置
 *
 * 只读文件尾部最多 64KB + 22 字节，与包体大小无关。
 *
 * @param resource $fp
 * @return array{entry_count: int, cd_offset: int, cd_size: int}|null
 */
function apkcheck_read_eocd($fp, int $size): ?array
{
    $tailLen = (int)min($size, 65535 + 22);
    if (fseek($fp, $size - $tailLen) !== 0) {
        return null;
    }
    $tail = fread($fp, $tailLen);
    if ($tail === false) {
        return null;
    }

    $eocdPos = strrpos($tail, "\x50\x4B\x05\x06");
    if ($eocdPos === false || strlen($tail) - $eocdPos < 22) {
        return null;
    }

    /*
     * EOCD：0 签名(4) 4 磁盘(2) 6 起始磁盘(2) 8 本盘条目(2)
     * 10 总条目(2) 12 中央目录大小(4) 16 中央目录偏移(4) 20 注释长度(2)
     */
    $info = @unpack('vcount/VcdSize/VcdOffset', substr($tail, $eocdPos + 10, 10));
    if ($info === false) {
        return null;
    }
    $count  = $info['count'];
    $cdSize = $info['cdSize'];
    $offset = $info['cdOffset'];

    // ZIP64：走定位器拿真实值
    if ($count === 0xFFFF || $offset === 0xFFFFFFFF || $cdSize === 0xFFFFFFFF) {
        $locatorPos = strrpos($tail, "\x50\x4B\x06\x07");
        if ($locatorPos === false || strlen($tail) - $locatorPos < 16) {
            return null;
        }
        $locInfo = @unpack('Pz64Offset', substr($tail, $locatorPos + 8, 8));
        if ($locInfo === false || $locInfo['z64Offset'] < 0 || $locInfo['z64Offset'] >= $size) {
            return null;
        }
        $here = ftell($fp);
        fseek($fp, $locInfo['z64Offset']);
        $z64 = fread($fp, 56);
        fseek($fp, $here);
        if ($z64 === false || strlen($z64) < 56 || substr($z64, 0, 4) !== "\x50\x4B\x06\x06") {
            return null;
        }
        // ZIP64 EOCD：32 总条目(8) 40 中央目录大小(8) 48 中央目录偏移(8)
        $z64Info = @unpack('Pcount/PcdSize/PcdOffset', substr($z64, 32, 24));
        if ($z64Info === false) {
            return null;
        }
        $count  = $z64Info['count'];
        $cdSize = $z64Info['cdSize'];
        $offset = $z64Info['cdOffset'];
    }

    if ($offset < 0 || $offset > $size || $cdSize < 0) {
        return null;
    }

    return [
        'entry_count' => max(0, (int)$count),
        'cd_offset'   => (int)$offset,
        'cd_size'     => (int)min($cdSize, $size - $offset),
    ];
}

/**
 * 在中央目录字节流里搜索特征字符串
 *
 * 这是整个检测最快的部分：纯 C 级 strpos，不构建 PHP 数组。
 * 目录较小时一次性读入；超大目录分块读入（块间重叠 64KB，避免长文件名被切断）。
 *
 * @param resource $fp
 * @return array{hits: array<string, bool>, scanned: int, truncated: bool}|null 超时返回 null
 */
function apkcheck_scan_central_dir($fp, int $cdOffset, int $cdSize, float $deadline): ?array
{
    // 目标字面量：全部是中央目录里必然原样出现的字符串
    $targets = [
        'manifest'    => 'AndroidManifest.xml',
        'dex'         => 'classes.dex',
        'arsc'        => 'resources.arsc',
        'res_dir'     => 'res/',
        'native_lib'  => 'lib/',
        'assets'      => 'assets/',
        'jar_meta'    => 'META-INF/MANIFEST.MF',
        'meta_inf'    => 'META-INF/',
        'sig_sf'      => '.SF',
        'sig_rsa'     => '.RSA',
        'sig_dsa'     => '.DSA',
        'sig_ec'      => '.EC',
        'dex_ext'     => '.dex',
        'jar_ext'     => '.jar',
        'apk_ext'     => '.apk',
    ];

    // 需要做内容校验的目标：命中时顺便记下条目头在文件里的绝对偏移
    $contentTargets = ['manifest', 'dex', 'arsc'];

    $hits = array_fill_keys(array_keys($targets), false);
    $hdr  = ['manifest' => null, 'dex' => null, 'arsc' => null];

    $allFound = static function () use (&$hits): bool {
        foreach ($hits as $v) {
            if (!$v) {
                return false;
            }
        }
        return true;
    };

    /**
     * 在一段缓冲区里匹配目标；对内容校验目标，还要往回 46 字节验证
     * 那确实是一条中央目录记录，从而拿到条目头偏移（顺带保证名字是精确匹配）
     */
    $process = static function (string $buf, int $bufStart) use (&$hits, &$hdr, $targets, $contentTargets): void {
        foreach ($targets as $key => $needle) {
            if ($hits[$key]) {
                continue;
            }
            $p = strpos($buf, $needle);
            if ($p === false) {
                continue;
            }
            if (!in_array($key, $contentTargets, true)) {
                $hits[$key] = true;
                continue;
            }
            /*
             * 这三个是「必须在根目录」的条目，要求精确匹配，否则
             * assets/classes.dex 会被误判成根目录的 classes.dex。
             * 判定方法：命中位置往前 46 字节必须正好是一条中央目录记录头 PK\x01\x02。
             * 满足该条件时，命中位置就是条目名的起始位置，即名字以 needle 开头。
             */
            $nlen   = strlen($needle);
            $offset = null;
            while ($p !== false) {
                if ($p >= 46 && substr($buf, $p - 46, 4) === "\x50\x4B\x01\x02") {
                    $declared = unpack('v', substr($buf, $p - 46 + 28, 2))[1];
                    if ($declared >= $nlen) {
                        $offset = $bufStart + $p - 46;
                        break;
                    }
                }
                $p = strpos($buf, $needle, $p + 1);
            }
            if ($offset === null) {
                continue;   // 只是某个路径里包含了这个名字，不算根目录命中
            }
            $hits[$key] = true;
            $hdr[$key]  = $offset;
        }
    };

    $scanned   = 0;
    $truncated = false;

    if (fseek($fp, $cdOffset) !== 0) {
        return null;
    }

    if ($cdSize <= APKCHECK_MAX_CD_SCAN) {
        $buf = $cdSize > 0 ? fread($fp, $cdSize) : '';
        if ($buf === false) {
            return null;
        }
        $scanned = strlen($buf);
        $process($buf, $cdOffset);
        unset($buf);
    } else {
        // 分块扫描：块大小 2MB，重叠 64KB（ZIP 文件名最长 65535 字节）
        $chunk   = APKCHECK_CD_CHUNK;
        $overlap = 65536;
        $pos     = 0;
        $carry   = '';
        while ($pos < $cdSize) {
            if ($deadline > 0 && microtime(true) > $deadline) {
                return null;
            }
            $len = (int)min($chunk, $cdSize - $pos);
            $buf = fread($fp, $len);
            if ($buf === false || $buf === '') {
                break;
            }
            $bufStart = $cdOffset + $pos - strlen($carry);
            $buf      = $carry . $buf;
            $scanned += $len;
            $process($buf, $bufStart);
            if ($allFound()) {
                // 全部命中，提前收工
                $pos = $cdSize;
                break;
            }
            $carry = substr($buf, -$overlap);
            $pos  += $len;
            unset($buf);
        }
        $truncated = $scanned < $cdSize;
        unset($carry);
    }

    // 签名块：META-INF/ 下存在 .SF/.RSA/.DSA/.EC 之一
    $hits['signature'] = $hits['meta_inf']
        && ($hits['sig_sf'] || $hits['sig_rsa'] || $hits['sig_dsa'] || $hits['sig_ec']);

    return [
        'hits'      => $hits,
        'hdr'       => $hdr,
        'scanned'   => $scanned,
        'truncated' => $truncated,
    ];
}

/**
 * 不依赖 zip 扩展，直接从包里读某个条目的前 N 字节
 *
 * 流程：中央目录条目头 → 本地文件头 → 定位数据区 →
 * 存储的直接读，deflate 的用增量 inflate 只解压前 64KB。
 * 完全不碰 libzip，因此没有 ZipArchive::open 在大量条目下的高昂开销，
 * 内存占用与条目大小无关。
 *
 * @param resource $fp
 * @param int $cdHeaderOffset apkcheck_scan_central_dir() 返回的条目头偏移
 * @return string|null null 表示读不到（不参与打分）
 */
function apkcheck_read_entry_head_native($fp, int $cdHeaderOffset, int $need = 8): ?string
{
    if ($cdHeaderOffset < 0 || fseek($fp, $cdHeaderOffset) !== 0) {
        return null;
    }
    $h = fread($fp, 46);
    if ($h === false || strlen($h) < 46 || substr($h, 0, 4) !== "\x50\x4B\x01\x02") {
        return null;
    }

    $method   = unpack('v', substr($h, 10, 2))[1];
    $compSize = unpack('V', substr($h, 20, 4))[1];
    $uncomp   = unpack('V', substr($h, 24, 4))[1];
    $nameLen  = unpack('v', substr($h, 28, 2))[1];
    $extraLen = unpack('v', substr($h, 30, 2))[1];
    $localOff = unpack('V', substr($h, 42, 4))[1];

    // ZIP64：从扩展字段里取真实尺寸
    if ($compSize === 0xFFFFFFFF || $uncomp === 0xFFFFFFFF || $localOff === 0xFFFFFFFF) {
        fseek($fp, $cdHeaderOffset + 46 + $nameLen);
        $extra = $extraLen > 0 ? fread($fp, $extraLen) : '';
        $p = 0;
        while ($p + 4 <= strlen($extra)) {
            $hid  = unpack('v', substr($extra, $p, 2))[1];
            $hlen = unpack('v', substr($extra, $p + 2, 2))[1];
            $body = substr($extra, $p + 4, $hlen);
            if ($hid === 0x0001) {
                $i = 0;
                if ($uncomp === 0xFFFFFFFF && strlen($body) >= $i + 8) {
                    $uncomp = unpack('P', substr($body, $i, 8))[1];
                    $i += 8;
                }
                if ($compSize === 0xFFFFFFFF && strlen($body) >= $i + 8) {
                    $compSize = unpack('P', substr($body, $i, 8))[1];
                    $i += 8;
                }
                if ($localOff === 0xFFFFFFFF && strlen($body) >= $i + 8) {
                    $localOff = unpack('P', substr($body, $i, 8))[1];
                }
                break;
            }
            $p += 4 + $hlen;
        }
    }

    // 本地文件头：0 签名(4) 4 版本(2) 6 标志(2) 8 方法(2) 26 名字长(2) 28 扩展长(2)
    if ($localOff < 0 || fseek($fp, $localOff) !== 0) {
        return null;
    }
    $lh = fread($fp, 30);
    if ($lh === false || strlen($lh) < 30 || substr($lh, 0, 4) !== "\x50\x4B\x03\x04") {
        return null;
    }
    $lNameLen  = unpack('v', substr($lh, 26, 2))[1];
    $lExtraLen = unpack('v', substr($lh, 28, 2))[1];
    $dataOff   = $localOff + 30 + $lNameLen + $lExtraLen;

    if ($compSize <= 0) {
        return '';
    }

    // 未压缩：直接读
    if ($method === 0) {
        if (fseek($fp, $dataOff) !== 0) {
            return null;
        }
        $raw = fread($fp, (int)min($compSize, $need));
        return $raw === false ? null : $raw;
    }

    // deflate：增量解压，最多读 64KB 就够拿到头部
    if ($method !== 8 || !function_exists('inflate_init')) {
        return null;
    }

    $inflater  = inflate_init(ZLIB_ENCODING_RAW);
    $out       = '';
    $pos       = $dataOff;
    $remaining = $compSize;
    while ($remaining > 0 && strlen($out) < $need) {
        $chunkLen = (int)min(65536, $remaining);
        if (fseek($fp, $pos) !== 0) {
            break;
        }
        $chunk = fread($fp, $chunkLen);
        if ($chunk === false || $chunk === '') {
            break;
        }
        $piece = @inflate_add($inflater, $chunk, ZLIB_SYNC_FLUSH);
        if ($piece === false) {
            break;
        }
        $out       .= $piece;
        $pos       += strlen($chunk);
        $remaining -= strlen($chunk);
    }

    return substr($out, 0, $need);
}

/**
 * 一次性读取多个条目的头部字节（共用一次 ZipArchive 句柄）
 *
 * @param string[] $names
 * @return array<string, string> 读不到的条目不会出现在结果里
 */
function apkcheck_read_entry_heads(string $filePath, array $names, int $length = 8): array
{
    if (!class_exists('ZipArchive') || $names === []) {
        return [];
    }

    $zip = new ZipArchive();
    if (@$zip->open($filePath) !== true) {
        return [];
    }

    $out = [];
    foreach ($names as $name) {
        $data = $zip->getFromName($name, $length);
        if ($data !== false && $data !== null) {
            $out[$name] = $data;
        }
    }
    $zip->close();

    return $out;
}

/**
 * 是否合法的 Android 二进制 XML（AXML）头
 *
 * ResChunk：type = RES_XML_TYPE(0x0003)，header_size = 8 → 03 00 08 00
 */
function apkcheck_is_axml(string $head): bool
{
    return strlen($head) >= 4 && substr($head, 0, 4) === "\x03\x00\x08\x00";
}

/**
 * 是否合法的 dex 文件头（"dex\n" 前缀，如 dex\n035\0 / dex\n039\0）
 */
function apkcheck_is_dex(string $head): bool
{
    return strlen($head) >= 4 && substr($head, 0, 4) === "dex\n";
}

/**
 * 是否合法的 resources.arsc 头（ResChunk type = RES_TABLE_TYPE = 0x0002）
 */
function apkcheck_is_arsc(string $head): bool
{
    return strlen($head) >= 2 && substr($head, 0, 2) === "\x02\x00";
}

/**
 * 根据命中特征推测包的形态，给出人类可读提示
 *
 * @param array<string, bool> $hits
 * @param array<string, bool|null> $contentOk
 * @return string[]
 */
function apkcheck_describe_structure(array $hits, array $contentOk): array
{
    $hasDex  = $hits['dex'] && $contentOk['dex'] !== false;
    $hasArsc = $hits['arsc'] && $contentOk['arsc'] !== false;
    $warnings = [];

    if ($hasDex && $hasArsc) {
        return $warnings;   // 常规完整包，无需提示
    }

    if (!$hasDex && $hits['dex_ext'] && ($hits['assets'] || $hits['native_lib'])) {
        $warnings[] = 'dex 不在根目录，但 assets/ 或 lib/ 下有 .dex/.jar：典型的加固 / 加壳包（梆梆、360、腾讯乐固等）';
    } elseif (!$hasDex && $hasArsc) {
        $warnings[] = '只有 resources.arsc 没有 classes.dex：可能是资源分包（config split）或 RRO 覆盖包';
    } elseif (!$hasArsc && $hasDex) {
        $warnings[] = '只有 classes.dex 没有 resources.arsc：无资源的纯代码包，或 split 出的代码包';
    } elseif ($hits['native_lib']) {
        $warnings[] = '没有 classes.dex / resources.arsc，但含 lib/：极可能是 App Bundle 拆出的 ABI 分包';
    } elseif ($hits['assets']) {
        $warnings[] = '没有 classes.dex / resources.arsc，但含 assets/：可能是 Asset Pack（资源分包）';
    } else {
        $warnings[] = '既没有 classes.dex 也没有 resources.arsc：结构不完整，需结合积分判断是否接受';
    }

    return $warnings;
}

/**
 * level 字段的中文说明
 *
 * invalid            无法判定（路径/权限/体积等问题）
 * not_zip            不是 ZIP 容器
 * broken_zip         是 ZIP 但结构损坏，或内容校验不通过（硬校验模式）
 * plain_zip          合法 ZIP，但积分不足（无 AndroidManifest.xml 等）
 * apk_manifest_only  有 manifest，但无 dex / arsc（split、asset pack、加壳包等）
 * apk_complete       有 manifest，且含 dex 或 arsc（常规完整 APK）
 */
function apkcheck_level_label(string $level): string
{
    return [
        'invalid'           => '无法判定',
        'not_zip'           => '非 ZIP 容器',
        'broken_zip'        => 'ZIP 结构损坏',
        'plain_zip'         => '普通 ZIP 压缩包',
        'apk_manifest_only' => '仅有 Manifest 的 APK（分包/资源包/加壳包）',
        'apk_complete'      => '完整 APK',
    ][$level] ?? $level;
}

/**
 * 字节数转人类可读体积
 */
function apkcheck_hsize(int|float $bytes): string
{
    $units = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    $bytes = (float)$bytes;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    return $i === 0 ? ((int)$bytes . ' ' . $units[$i]) : (round($bytes, 1) . ' ' . $units[$i]);
}

/**
 * 通过 zip 扩展列举压缩包内所有条目
 *
 * 注意：会构建 PHP 数组，大包下有明显内存开销，仅在 options['entries'] = true 时使用。
 *
 * @return string[]|null 失败返回 null
 */
function apkcheck_list_entries_by_ziparchive(string $filePath): ?array
{
    $zip = new ZipArchive();
    $err = @$zip->open($filePath);
    if ($err !== true) {
        return null;
    }

    $entries = [];
    $total   = $zip->numFiles;
    for ($i = 0; $i < $total; $i++) {
        $stat = $zip->statIndex($i);
        if ($stat !== false && isset($stat['name'])) {
            $entries[] = $stat['name'];
        }
    }
    $zip->close();

    return $entries;
}

/**
 * 手动解析 ZIP 中央目录列举条目（zip 扩展不可用时的兜底方案）
 *
 * @return string[]|null 失败返回 null
 */
function apkcheck_list_entries_manual(string $filePath): ?array
{
    $fp = @fopen($filePath, 'rb');
    if ($fp === false) {
        return null;
    }

    $size = filesize($filePath);
    $eocd = apkcheck_read_eocd($fp, $size);
    if ($eocd === null) {
        fclose($fp);
        return null;
    }

    // 防止恶意声明超大条目数导致死循环
    $count = min($eocd['entry_count'], 100000);
    fseek($fp, $eocd['cd_offset']);

    $entries = [];
    for ($i = 0; $i < $count; $i++) {
        $head = fread($fp, 46);
        if (strlen($head) < 46 || substr($head, 0, 4) !== "\x50\x4B\x01\x02") {
            break;
        }
        $h        = unpack('vnameLen/vextraLen/vcommentLen', substr($head, 28, 6));
        $entries[] = fread($fp, $h['nameLen']);
        fseek($fp, $h['extraLen'] + $h['commentLen'], SEEK_CUR);
    }
    fclose($fp);

    return $entries;
}

/**
 * 根据文件头魔数猜测真实文件类型，用于给出更友好的提示
 */
function apkcheck_guess_type_by_magic(string $magic): string
{
    $map = [
        "\x89PNG"          => 'PNG 图片',
        "\xFF\xD8\xFF"     => 'JPEG 图片',
        'GIF8'             => 'GIF 图片',
        'BM'               => 'BMP 图片',
        'RIFF'             => 'WEBP / WAV 文件',
        '%PDF'             => 'PDF 文档',
        "\x1F\x8B"         => 'GZIP 压缩包',
        "\x37\x7A\xBC\xAF" => '7-Zip 压缩包',
        'Rar!'             => 'RAR 压缩包',
        "\xFD7zXZ"         => 'XZ 压缩包',
        'MZ'               => 'Windows PE / EXE 可执行文件',
        "\x7FELF"          => 'ELF 可执行文件',
        "\xCA\xFE\xBA\xBE" => 'Java Class / Mach-O 文件',
        'OggS'             => 'OGG 音频',
        'ID3'              => 'MP3 音频',
        'ftyp'             => 'MP4 视频',
    ];

    foreach ($map as $sig => $label) {
        if (str_starts_with($magic, $sig)) {
            return $label;
        }
    }
    if (str_starts_with($magic, 'PK')) {
        return 'ZIP 类文件（非标准 APK）';
    }

    return '';
}

/**
 * 把检测结果格式化为人类可读的文本
 *
 * @param bool $explain 是否输出命中特征明细
 */
function apkcheck_format(array $result, bool $explain = false): string
{
    $head = $result['is_apk'] ? '[PASS] 是 APK' : '[FAIL] 不是 APK';
    $line = sprintf(
        '%s | score=%d/%d | level=%s | code=%s | %s',
        $head,
        $result['score'] ?? 0,
        $result['threshold'] ?? 0,
        $result['level'] ?? '-',
        $result['code'],
        $result['message']
    );
    if ($explain && !empty($result['features'])) {
        $parts = [];
        foreach ($result['features'] as $f) {
            $parts[] = $f['label'] . '(' . ($f['points'] >= 0 ? '+' : '') . $f['points'] . ')';
        }
        $line .= PHP_EOL . '        命中: ' . implode('  ', $parts);
    }
    foreach ($result['warnings'] ?? [] as $w) {
        $line .= PHP_EOL . '        warn: ' . $w;
    }

    return $line;
}

// 库到此结束，不含任何入口代码：
// require 进来不会输出任何东西，命令行用法见 cli.php。
