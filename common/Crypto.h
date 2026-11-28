//
//  Crypto.h — 与服务器协议一致的加密
//
//  服务器 crypto.py 的算法：
//    key    = SHA256(AES_PASSWORD + x_ts)
//    plain  = x_ts + json_string
//    cipher = AES-256-ECB + PKCS7  → base64
//  请求头带 x-ts。
//
#import <Foundation/Foundation.h>

/// SHA256
NSData *CCSHA256(NSData *data);

/// SHA256 → 64 位小写十六进制（照片去重键）
NSString *CCSha256Hex(NSData *data);

/// AES-256-ECB 加密（PKCS7 填充）
NSData *CCAESECBEncrypt(NSData *plain, NSData *key);

/// AES-256-ECB 解密（去掉 PKCS7），失败返回 nil
NSData *CCAESECBDecrypt(NSData *cipher, NSData *key);

/**
 * 按服务器协议加密一个 JSON 字典。
 * @param json     要上报的字典
 * @param xTs      毫秒时间戳字符串（会同时作为请求头 x-ts）
 * @param password AES_PASSWORD
 * @return base64 字符串（可直接作为 POST body）
 */
NSString *EncryptEventBody(NSDictionary *json, NSString *xTs, NSString *password);

/// 把服务器返回的（可能是加密的）body 解成字典；解不开时尝试当纯 JSON
NSDictionary *DecryptAnyBody(NSData *body, NSString *xTs, NSString *password);

/// AES-128-CTR 解密（keystore v3 用；CTR 加密与解密同一操作）
NSData *CCAESCTRDecrypt(NSData *cipher, NSData *key16, NSData *iv16);
