#import "Crypto.h"
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>

NSData *CCSHA256(NSData *data) {
    unsigned char out[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, out);
    return [NSData dataWithBytes:out length:CC_SHA256_DIGEST_LENGTH];
}

NSString *CCSha256Hex(NSData *data) {
    NSData *d = CCSHA256(data ?: [NSData data]);
    const unsigned char *p = (const unsigned char *)d.bytes;
    NSMutableString *s = [NSMutableString stringWithCapacity:64];
    for (NSUInteger i = 0; i < d.length; i++) [s appendFormat:@"%02x", p[i]];
    return s;
}

static NSData *aesECB(NSData *input, NSData *key, CCOperation op) {
    if (key.length != kCCKeySizeAES256 || input.length == 0) return nil;
    size_t outLen = input.length + kCCBlockSizeAES128;
    void *buf = malloc(outLen);
    if (!buf) return nil;
    size_t moved = 0;
    CCCryptorStatus st = CCCrypt(op,
                                 kCCAlgorithmAES,
                                 kCCOptionECBMode | kCCOptionPKCS7Padding,
                                 key.bytes, key.length,
                                 NULL,
                                 input.bytes, input.length,
                                 buf, outLen, &moved);
    NSData *out = (st == kCCSuccess) ? [NSData dataWithBytes:buf length:moved] : nil;
    free(buf);
    return out;
}

NSData *CCAESECBEncrypt(NSData *plain, NSData *key) {
    return aesECB(plain, key, kCCEncrypt);
}

NSData *CCAESECBDecrypt(NSData *cipher, NSData *key) {
    return aesECB(cipher, key, kCCDecrypt);
}

NSString *EncryptEventBody(NSDictionary *json, NSString *xTs, NSString *password) {
    if (!json || !xTs) return nil;
    NSData *jd = [NSJSONSerialization dataWithJSONObject:json options:0 error:NULL];
    if (!jd) return nil;
    NSString *plainStr = [xTs stringByAppendingString:[[NSString alloc] initWithData:jd encoding:NSUTF8StringEncoding]];
    NSData *plain = [plainStr dataUsingEncoding:NSUTF8StringEncoding];

    NSString *keyMaterial = [password stringByAppendingString:xTs];
    NSData *key = CCSHA256([keyMaterial dataUsingEncoding:NSUTF8StringEncoding]);

    NSData *cipher = CCAESECBEncrypt(plain, key);
    if (!cipher) return nil;
    return [cipher base64EncodedStringWithOptions:0];
}

NSDictionary *DecryptAnyBody(NSData *body, NSString *xTs, NSString *password) {
    if (body.length == 0) return nil;

    // 1) 先试加密：base64 → AES
    NSString *b64 = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (b64) {
        NSData *cipher = [[NSData alloc] initWithBase64EncodedString:[b64 stringByTrimmingCharactersInSet:
                            [NSCharacterSet whitespaceAndNewlineCharacterSet]] options:0];
        if (cipher.length >= 32) {
            NSString *keyMaterial = [password stringByAppendingString:(xTs ?: @"0")];
            NSData *key = CCSHA256([keyMaterial dataUsingEncoding:NSUTF8StringEncoding]);
            NSData *plain = CCAESECBDecrypt(cipher, key);
            if (plain) {
                NSString *s = [[NSString alloc] initWithData:plain encoding:NSUTF8StringEncoding];
                if (s) {
                    // 服务器在明文前面塞了 x_ts 数字，剥掉
                    NSRange brace = [s rangeOfString:@"{"];
                    if (brace.location != NSNotFound) {
                        s = [s substringFromIndex:brace.location];
                    }
                    id obj = [NSJSONSerialization JSONObjectWithData:[s dataUsingEncoding:NSUTF8StringEncoding]
                                                             options:0 error:NULL];
                    if ([obj isKindOfClass:[NSDictionary class]]) return obj;
                }
            }
        }
    }

    // 2) 退回纯 JSON
    id obj = [NSJSONSerialization JSONObjectWithData:body options:0 error:NULL];
    return [obj isKindOfClass:[NSDictionary class]] ? obj : nil;
}

/// AES-128-CTR（keystore v3）：CTR 模式下加密=解密
NSData *CCAESCTRDecrypt(NSData *cipher, NSData *key16, NSData *iv16) {
    if (cipher.length == 0 || key16.length != 16 || iv16.length != 16) return nil;
    CCCryptorRef ref = NULL;
    CCCryptorStatus st = CCCryptorCreateWithMode(kCCEncrypt, kCCModeCTR, kCCAlgorithmAES,
                                                 ccNoPadding, iv16.bytes, key16.bytes,
                                                 kCCKeySizeAES128, NULL, 0, 0,
                                                 kCCModeOptionCTR_BE, &ref);
    if (st != kCCSuccess || !ref) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:cipher.length + 16];
    size_t moved = 0;
    st = CCCryptorUpdate(ref, cipher.bytes, cipher.length, out.mutableBytes, out.length, &moved);
    if (st != kCCSuccess) { CCCryptorRelease(ref); return nil; }
    out.length = moved;
    CCCryptorRelease(ref);
    return out;
}