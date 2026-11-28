#import "KernProbe.h"
#import <mach/mach.h>
#import <mach/task_info.h>
#import <unistd.h>
#import <dlfcn.h>

// libproc 头文件不在 iOS SDK 里，函数本身导出，自己声明
extern int proc_listallpids(void *buffer, int buffersize);

@implementation KernProbe

+ (NSDictionary *)report {
    NSMutableDictionary *out = [NSMutableDictionary dictionary];

    out[@"uid"] = @(getuid());
    out[@"euid"] = @(geteuid());
    out[@"pid"] = @(getpid());

    // ---------------------------------------------------------- 进程枚举
    pid_t *pids = (pid_t *)malloc(sizeof(pid_t) * 2048);
    int count = 0;
    if (pids) {
        count = proc_listallpids(pids, sizeof(pid_t) * 2048);
        out[@"procList.count"] = @(count > 0 ? count : 0);
    } else {
        out[@"procList.error"] = @"malloc failed";
    }

    // ---------------------------------------------------------- task_for_pid
    if (pids && count > 0) {
        mach_port_t self_task = mach_task_self();
        int tried = 0, ok = 0;
        int firstKr = 0;
        NSMutableArray *okPids = [NSMutableArray array];

        for (int i = 0; i < count && tried < 30; i++) {
            pid_t p = pids[i];
            if (p <= 0 || p == getpid()) continue;

            mach_port_t t = MACH_PORT_NULL;
            kern_return_t kr = task_for_pid(self_task, p, &t);
            tried++;
            if (kr == KERN_SUCCESS) {
                ok++;
                if (okPids.count < 10) [okPids addObject:@(p)];
                if (t != MACH_PORT_NULL) {
                    // 试读一下对方的 task 基本信息，确认端口真能用
                    struct task_basic_info basic;
                    mach_msg_type_number_t sz = TASK_BASIC_INFO_COUNT;
                    task_info(t, TASK_BASIC_INFO, (task_info_t)&basic, &sz);
                    mach_port_deallocate(self_task, t);
                }
            } else if (firstKr == 0) {
                firstKr = kr;
            }
        }
        out[@"taskForPid.tried"] = @(tried);
        out[@"taskForPid.ok"] = @(ok);
        out[@"taskForPid.firstKr"] = @(firstKr);
        if (okPids.count) out[@"taskForPid.pids"] = okPids;
    }
    if (pids) free(pids);

    // ---------------------------------------------------------- 沙箱放宽程度
    NSArray *probes = @[
        @"/var/mobile/Library/Preferences",
        @"/var/mobile/Containers/Data/Application",
        @"/var/mobile/Library/Keychains",
        @"/private/var/mobile/Library/SMS",
        @"/var/mobile/Library/AddressBook",
    ];
    NSMutableDictionary *sb = [NSMutableDictionary dictionary];
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in probes) {
        NSError *err = nil;
        NSArray *list = [fm contentsOfDirectoryAtPath:p error:&err];
        sb[p] = list ? [NSString stringWithFormat:@"ok(%lu)", (unsigned long)list.count]
                     : [NSString stringWithFormat:@"deny: %@", err.localizedDescription ?: @"?"];
    }
    out[@"sandbox"] = sb;

    // ---------------------------------------------------------- 是否有内核符号可借
    void *ps = dlopen("/usr/lib/libsqlite3.dylib", RTLD_LAZY);
    out[@"dlopen.sqlite3"] = ps ? @"ok" : @"fail";

    return out;
}

@end
