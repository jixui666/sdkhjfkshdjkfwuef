//
//  KernProbe.h — 探测当前进程实际拿到哪些内核级能力
//
//  目的：判断我们到底是「只有沙箱放宽」还是「真的有内核读写」。
//  如果真的能 task_for_pid，那注入就不用 135 秒了 —— 直接 dlopen 对方进程。
//
#import <Foundation/Foundation.h>

@interface KernProbe : NSObject

/// 返回一份能力报告：
///   taskForPid.ok / tried / firstKr      —— task_for_pid 能不能拿到别的进程
///   procList.count                        —— 能枚举到多少进程
///   sandbox.paths                         —— 几个通常被拦的路径能不能读
///   rootless / uid                        —— 身份信息
+ (NSDictionary *)report;

@end
