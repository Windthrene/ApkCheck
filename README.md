# ApkCheck

一个零依赖的单文件 PHP 库，用来判断「这个文件是不是 APK」。

不靠文件扩展名、不靠 MIME，而是给 ZIP 包里的特征**打分**：命中一个特征加对应分数，
总分达到门槛就认为是 APK。这样只含 `classes.dex`、或只含 `resources.arsc` 的包都能通过，
而把文本文件改名成 `classes.dex` 的伪造包会被**倒扣**成负分。

针对低配服务器（1 核 1G）做过优化：**检测耗时和内存占用与包体大小基本无关**，
112MB 的真实 APK 实测 5ms / 内存峰值 6MB。

## 用法

主函数只返回一个整数，不做任何输出：

```php
require_once 'apkcheck.php';

$score = apkcheck_score('/path/to/app.apk');   // => 22

if ($score >= 7) {
    // 是 APK
}
```

需要诊断信息（命中了哪些特征、为什么被拒）时用 `apkcheck_verify()`：

```php
$r = apkcheck_verify('/path/to/app.apk');
$r['score'];      // 22
$r['is_apk'];     // true
$r['level'];      // apk_complete
$r['code'];       // OK
$r['features'];   // [['key'=>'manifest','points'=>4,'label'=>'AndroidManifest.xml'], ...]
$r['warnings'];   // 结构提示，例如「可能是 App Bundle 拆出的 ABI 分包」
$r['entry_count'];// 2100
```

### 选项

| 选项 | 默认 | 说明 |
|---|---|---|
| `threshold` | 7 | 及格线（只影响 `verify()` 的 `is_apk`，不影响分数） |
| `weights` | 见下表 | 覆盖单个或全部特征权重 |
| `maxSize` | 0 | 体积上限（字节），**0 = 不限制** |
| `minSize` | 128 | 体积下限，用于排除空文件 |
| `content` | true | 是否读取条目头部做魔数校验 |
| `deep` | false | 硬校验：内容不合法直接判否，而不是扣分 |
| `timeout` | 0 | 扫描超时秒数，0 = 不限 |
| `entries` | false | 是否在结果里返回完整条目列表（大包下很慢，默认关） |

```php
// 自定义门槛与权重
apkcheck_verify($path, ['threshold' => 10, 'weights' => ['dex' => 5]]);

// 自我保护：只允许检测 256MB 以内的文件
apkcheck_verify($path, ['maxSize' => 256 * 1024 * 1024]);
```

> 体积限制该由 `php.ini` / nginx 管，所以库默认**不限制**。需要自我保护时再传 `maxSize`。

## 打分表

| 特征 | 分 | 特征 | 分 |
|---|---|---|---|
| AndroidManifest.xml | +4 | res/ 目录 | +2 |
| Manifest 头部是合法 AXML | +2 | lib/ 原生库 | +2 |
| classes.dex（含 classesN） | +3 | META-INF 签名 | +2 |
| dex 魔数正确 | +1 | dex 藏于 assets/lib（加壳） | +2 |
| resources.arsc | +3 | META-INF/MANIFEST.MF | +1 |
| arsc 魔数正确 | +1 | assets/ 目录 | +1 |
| **Manifest 非 AXML** | **−4** | **arsc 内容非法** | **−3** |
| **dex 内容非法** | **−3** | **包内嵌 .apk（集合包）** | **−2** |

默认门槛 **7 分** = `manifest(4) + AXML(2)` 之后再命中任意 1 分特征。
参考：完整包 17~22 分、只有 dex 10 分、只有 arsc 10~12 分、ABI 分包 8 分、
Asset Pack 7 分、普通 zip 0 分、伪造包 −10 分。

## 为什么它能过严格规则会误杀的那些包

这些都是**合法** APK，但没有根目录的 dex/arsc，容易被一刀切的规则拒绝：

- App Bundle 拆出的 ABI 分包（`lib/<abi>/*.so` + manifest）
- Asset Pack（只有 `assets/`）
- 加固加壳包（dex 被搬进 `assets/` 或 `lib/`）
- 资源分包 / RRO 覆盖包（有 arsc 无 dex）

积分制下它们都能拿到 7~12 分正常通过，并通过 `warnings` 告诉你它属于哪一种。

## 性能

瓶颈曾在 `ZipArchive::open()`（万级条目下要几百毫秒），现在整个扫描层是自己实现的：

1. 只读文件头 4 字节判断容器
2. 只读文件尾部定位 EOCD，直接拿到条目数与中央目录偏移，**不遍历条目**
3. 特征匹配 = 对中央目录字节流做 `strpos`，不构建 PHP 数组
4. 内容校验只读取 3 个目标条目的前 8 字节，deflate 走增量解压（最多 64KB）
5. 中央目录超过 8MB 时分块扫描，支持提前收工与超时中止

实测（PHP 8.2，`memory_limit=128M`）：

| 场景 | 耗时 | 内存峰值 |
|---|---|---|
| 112MB 真实 APK（2100 条目） | **5 ms** | 6 MB |
| 256MB 包 | 2 ms | 6 MB |
| 5 万条目包 | **21 ms**（优化前 930 ms） | 6 MB |
| 小包 | 4 ms | 2 MB |

`zip` / `zlib` 扩展缺失时会自动降级（跳过内容校验，少 3~4 分），仍可正常工作。

## Demo

前后端分离的上传示例：

- `demo.html` —— 纯静态前端，拖放上传、进度条、结果表格
- `api.php` —— 后端接口，`POST` 返回 JSON，`GET` 返回服务端限制与权重表

```bash
php -S 127.0.0.1:8099        # 然后浏览器打开 http://127.0.0.1:8099/demo.html
```

接口返回：

```json
{"ok":true,"name":"a.apk","size":117584379,"score":22,
 "threshold":7,"is_apk":true,"elapsed_ms":5.2,"memory_peak":"6 MB"}
```

## 目录结构

```
apkcheck.php   核心库，唯一文件，零依赖
api.php        Demo 的后端接口（JSON）
demo.html      Demo 的前端页面（纯静态）
samples/       测试样本：完整包、只有 dex、只有 arsc、ABI 分包、Asset Pack、
               加壳包、普通 zip、改名伪造包等各种结构
```

## 要求

PHP >= 7.4（推荐 8.x）。`zip` / `zlib` 扩展可选——缺失时跳过内容校验。
