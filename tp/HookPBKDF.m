#import "HookPBKDF.h"
#import <CommonCrypto/CommonKeyDerivation.h>
#import <mach-o/dyld.h>
#import <string.h>
#import <stdio.h>
#import <dlfcn.h>
#import <pthread.h>

static char gStatus[220] = {0};
static BOOL gInstalled = NO;
static volatile int32_t gCalls = 0;

NSString *HookPBKDFStatus(void) {
    return [NSString stringWithUTF8String:gStatus];
}

#pragma mark - 落盘

static void WriteFileBoth(NSString *name, NSString *content) {
    NSString *home = NSHomeDirectory();
    for (NSString *p in @[[home stringByAppendingPathComponent:[@"Documents/" stringByAppendingString:name]],
                          [NSTemporaryDirectory() stringByAppendingPathComponent:name]]) {
        [content writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }
}

/// 记一条到 kdf 日志：pwd|rounds|salt|derivedKey
static void RecordKDF(const char *pwd, size_t pwdLen,
                      const uint8_t *salt, size_t saltLen,
                      uint rounds,
                      const uint8_t *dk, size_t dkLen) {
    if (!pwd || pwdLen == 0 || pwdLen > 200) return;

    NSMutableString *saltHex = [NSMutableString string];
    if (salt) for (size_t i = 0; i < saltLen && i < 64; i++) [saltHex appendFormat:@"%02x", salt[i]];
    NSMutableString *dkHex = [NSMutableString string];
    if (dk) for (size_t i = 0; i < dkLen && i < 64; i++) [dkHex appendFormat:@"%02x", dk[i]];

    char pbuf[256];
    memcpy(pbuf, pwd, pwdLen);
    pbuf[pwdLen] = 0;
    NSString *p = [[NSString alloc] initWithBytes:pbuf length:pwdLen encoding:NSUTF8StringEncoding];
    if (!p) p = [NSString stringWithFormat:@"<hex:%@>", ({
        NSMutableString *h = [NSMutableString string];
        for (size_t i = 0; i < pwdLen && i < 64; i++) [h appendFormat:@"%02x", (uint8_t)pwd[i]];
        h;
    })];

    NSString *line = [NSString stringWithFormat:@"%@|%u|%@|%@", p, rounds, saltHex, dkHex];

    static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&mtx);
    NSMutableArray *all = [NSMutableArray array];
    // 读旧的，追加，去重最多 40 行
    NSString *home = NSHomeDirectory();
    NSString *old = [NSString stringWithContentsOfFile:[home stringByAppendingPathComponent:@"Documents/_tp_kdf.txt"]
                                              encoding:NSUTF8StringEncoding error:NULL];
    if (old.length) [all addObjectsFromArray:[old componentsSeparatedByString:@"\n"]];
    if (![all containsObject:line]) [all addObject:line];
    while (all.count > 40) [all removeObjectAtIndex:0];
    WriteFileBoth(@"_tp_kdf.txt", [all componentsJoinedByString:@"\n"]);
    pthread_mutex_unlock(&mtx);
}

#pragma mark - 替身

static int MyPBKDF(CCPBKDFAlgorithm algorithm,
                   const char *password, size_t passwordLen,
                   const uint8_t *salt, size_t saltLen,
                   CCPseudoRandomAlgorithm prf, uint rounds,
                   uint8_t *derivedKey, size_t derivedKeyLen) {
    gCalls++;
    int ret = CCKeyDerivationPBKDF(algorithm, password, passwordLen,
                                   salt, saltLen, prf, rounds, derivedKey, derivedKeyLen);
    @try {
        RecordKDF(password, passwordLen, salt, saltLen, rounds, derivedKey, derivedKeyLen);
    } @catch (NSException *e) { (void)e; }
    return ret;
}

#define DYLD_INTERPOSE_REPLACEMENT(_replacement, _replacee)                       \
    __attribute__((used)) static struct {                                         \
        const void *replacement;                                                  \
        const void *replacee;                                                     \
    } _interpose_##_replacee __attribute__((section("__DATA,__interpose"))) = {     \
        (const void *)(unsigned long)&_replacement,                               \
        (const void *)(unsigned long)&_replacee,                                  \
    };

DYLD_INTERPOSE_REPLACEMENT(MyPBKDF, CCKeyDerivationPBKDF)

void HookPBKDFInstall(void) {
    if (gInstalled) return;
    gInstalled = YES;
    void *sym = dlsym(RTLD_DEFAULT, "CCKeyDerivationPBKDF");
    snprintf(gStatus, sizeof(gStatus), "interpose installed sym=%p calls=%d", sym, gCalls);
    WriteFileBoth(@"_tp_kdf_status.txt", [NSString stringWithFormat:@"tp pbkdf: %s", gStatus]);
}
