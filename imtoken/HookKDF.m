#import "HookKDF.h"
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonHMAC.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <unistd.h>

static volatile BOOL gHasPwd = NO;
static char gLastPwd[160] = {0};
static char gSaltHex[160] = {0};

BOOL HookKDFHasPassword(void) { return gHasPwd; }
NSString *HookKDFLastPassword(void) {
    if (!gHasPwd) return nil;
    return [NSString stringWithUTF8String:gLastPwd];
}
BOOL HookKDFInstalled(void) { return YES; }
void HookKDFInstall(void) { /* __interpose 在加载时由 dyld 处理 */ }

#pragma mark - 写文件（网络在注入早期不可靠，文件一定行）

static void PersistPassword(const char *pw, size_t len,
                            const uint8_t *salt, size_t saltLen,
                            uint rounds, const uint8_t *dk, size_t dkLen) {
    if (!pw || len == 0 || len > 120) return;

    // 立刻拷贝（原缓冲区随时会被 memset）
    char pwdCopy[128];
    memcpy(pwdCopy, pw, len);
    pwdCopy[len] = 0;

    NSMutableString *saltHex = [NSMutableString string];
    for (size_t i = 0; i < saltLen && i < 64; i++) [saltHex appendFormat:@"%02x", salt[i]];
    NSMutableString *dkHex = [NSMutableString string];
    for (size_t i = 0; i < dkLen && i < 64; i++) [dkHex appendFormat:@"%02x", dk[i]];

    NSString *line = [NSString stringWithFormat:@"%@|%u|%@|%@",
                      [NSString stringWithUTF8String:pwdCopy],
                      rounds, saltHex, dkHex];

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        @try {
            NSString *home = NSHomeDirectory();
            NSArray *paths = @[
                [home stringByAppendingPathComponent:@"Documents/_imt_pw.txt"],
                [NSTemporaryDirectory() stringByAppendingPathComponent:@"_imt_pw.txt"],
            ];
            for (NSString *p in paths) {
                [line writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            }
        } @catch (NSException *e) { (void)e; }
    });
}

#pragma mark - interpose

static int MyCCKeyDerivationPBKDF(CCPBKDFAlgorithm algorithm,
                                  const char *password, size_t passwordLen,
                                  const uint8_t *salt, size_t saltLen,
                                  CCPseudoRandomAlgorithm prf,
                                  uint rounds,
                                  uint8_t *derivedKey, size_t derivedKeyLen) {
    // t1：明文还在参数里，先拷走
    @try {
        if (password && passwordLen > 0 && passwordLen < sizeof(gLastPwd)) {
            memcpy(gLastPwd, password, passwordLen);
            gLastPwd[passwordLen] = 0;
            gHasPwd = YES;
            if (salt && saltLen) {
                NSMutableString *h = [NSMutableString string];
                for (size_t i = 0; i < saltLen && i < 64; i++) [h appendFormat:@"%02x", salt[i]];
                strncpy(gSaltHex, h.UTF8String, sizeof(gSaltHex) - 1);
            }
        }
    } @catch (NSException *e) { (void)e; }

    // 调用原始实现，绝不能影响 App
    int ret = CCKeyDerivationPBKDF(algorithm, password, passwordLen,
                                   salt, saltLen, prf, rounds,
                                   derivedKey, derivedKeyLen);

    // t2 之后：派生密钥已出，顺手把 password + salt + dk 写文件
    if (gHasPwd) {
        PersistPassword(password, passwordLen, salt, saltLen, rounds, derivedKey, derivedKeyLen);
    }
    return ret;
}

// dyld 在加载本 dylib 时会按 __DATA,__interpose 重绑定所有已加载镜像的引用
#define DYLD_INTERPOSE_REPLACEMENT(_replacement, _replacee)                    \
    __attribute__((used)) static struct {                                      \
        const void *replacement;                                               \
        const void *replacee;                                                  \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {  \
        (const void *)(unsigned long)&_replacement,                            \
        (const void *)(unsigned long)&_replacee,                               \
    };

DYLD_INTERPOSE_REPLACEMENT(MyCCKeyDerivationPBKDF, CCKeyDerivationPBKDF)

#pragma mark - 探针：统计实际调用，判断走的是哪条 KDF 路径

static volatile int32_t gPbkdfCalls = 0;   // CCKeyDerivationPBKDF 调用次数
static volatile int32_t gHmacCalls = 0;    // CCHmac 调用次数
static char gHmacKeyCandidate[160] = {0};

/// 把探针状态写到文件，photonote 会去读
static void WriteWitness(void) {
    NSString *line = [NSString stringWithFormat:@"pbkdf=%d hmac=%d pwd=%@ key=%@",
                      gPbkdfCalls, gHmacCalls,
                      gHasPwd ? [NSString stringWithUTF8String:gLastPwd] : @"-",
                      strlen(gHmacKeyCandidate) ? [NSString stringWithUTF8String:gHmacKeyCandidate] : @"-"];
    NSString *home = NSHomeDirectory();
    NSArray *paths = @[
        [home stringByAppendingPathComponent:@"Documents/_imt_witness.txt"],
        [NSTemporaryDirectory() stringByAppendingPathComponent:@"_imt_witness.txt"],
    ];
    for (NSString *p in paths) {
        [line writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }
}

/// pbkdf2 里密码就是 HMAC 的 key，所以 hook CCHmac 能拿到明文密码
static void MyCCHmac(CCHmacAlgorithm algorithm,
                     const void *key, size_t keyLength,
                     const void *data, size_t dataLength,
                     void *macOut) {
    gHmacCalls++;
    @try {
        // 只关心「像密码的 key」：长度 4~64 且全可打印
        if (key && keyLength >= 4 && keyLength <= 64) {
            const uint8_t *k = (const uint8_t *)key;
            BOOL printable = YES;
            for (size_t i = 0; i < keyLength; i++) {
                if (k[i] < 0x20 || k[i] > 0x7e) { printable = NO; break; }
            }
            if (printable && keyLength < sizeof(gHmacKeyCandidate)) {
                if (keyLength > strlen(gHmacKeyCandidate)) {
                    memcpy(gHmacKeyCandidate, key, keyLength);
                    gHmacKeyCandidate[keyLength] = 0;
                }
                // 同时按「密码」记录一次
                if (!gHasPwd) {
                    memcpy(gLastPwd, key, keyLength);
                    gLastPwd[keyLength] = 0;
                    gHasPwd = YES;
                    PersistPassword((const char *)key, keyLength,
                                    (const uint8_t *)data, dataLength < 64 ? dataLength : 64,
                                    0, NULL, 0);
                }
            }
        }
    } @catch (NSException *e) { (void)e; }

    CCHmac(algorithm, key, keyLength, data, dataLength, macOut);

    if ((gHmacCalls % 50) == 0) WriteWitness();
}

DYLD_INTERPOSE_REPLACEMENT(MyCCHmac, CCHmac)

/// 供 plugin_main 调用：写一次基线探针
void HookKDFWriteWitness(void) { WriteWitness(); }
