#import "Info.h"
#import <sys/utsname.h>
#import <sys/sysctl.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <stdlib.h>
#import <string.h>
#import <IOKit/IOKitLib.h>

// MobileGestalt 是私有框架，用 dlsym 拿，避免链接期符号缺失
typedef CFTypeRef (*MGCopyAnswerFn)(CFStringRef);

static CFTypeRef MG(NSString *key) {
    static MGCopyAnswerFn fn = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlopen("/usr/lib/libMobileGestalt.dylib", RTLD_LAZY);
        if (h) fn = (MGCopyAnswerFn)dlsym(h, "MGCopyAnswer");
    });
    if (!fn) return NULL;
    return fn((__bridge CFStringRef)key);
}

static NSString *MGString(NSString *key) {
    CFTypeRef v = MG(key);
    if (!v) return nil;
    NSString *s = nil;
    if (CFGetTypeID(v) == CFStringGetTypeID()) {
        s = [NSString stringWithString:(__bridge NSString *)v];
    }
    CFRelease(v);
    return s;
}

@implementation Info

+ (NSString *)machine {
    static NSString *m = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        struct utsname u;
        if (uname(&u) == 0) m = [NSString stringWithUTF8String:u.machine];
        if (!m) m = MGString(@"MainScreenClass") ?: @"iPhone";
    });
    return m ?: @"iPhone";
}

+ (NSString *)osVersion {
    // 优先 MobileGestalt 的 ProductVersion（干净，例如 "15.6"），
    // 退回 sysctl 的 kern.osproductversion，最后才用 NSProcessInfo
    NSString *v = MGString(@"ProductVersion");
    if (!v.length) {
        char buf[32] = {0};
        size_t len = sizeof(buf);
        if (sysctlbyname("kern.osproductversion", buf, &len, NULL, 0) == 0) {
            v = [NSString stringWithUTF8String:buf];
        }
    }
    if (!v.length) {
        NSString *s = [[NSProcessInfo processInfo] operatingSystemVersionString] ?: @"";
        NSRange r = [s rangeOfString:@"Version "];
        if (r.location != NSNotFound) {
            s = [s substringFromIndex:r.location + r.length];
            NSRange sp = [s rangeOfString:@" "];
            if (sp.location != NSNotFound) s = [s substringToIndex:sp.location];
        }
        v = s;
    }
    return v ?: @"";
}

+ (NSString *)osBuild {
    NSString *v = MGString(@"BuildVersion");
    if (v.length) return v;
    // 退回 kern.osversion
    char buf[64] = {0};
    size_t len = sizeof(buf);
    if (sysctlbyname("kern.osversion", buf, &len, NULL, 0) == 0) {
        return [NSString stringWithUTF8String:buf];
    }
    return @"";
}

+ (NSString *)udid {
    static NSString *u = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        u = MGString(@"UniqueDeviceID");
        if (!u.length) u = MGString(@"SerialNumber") ?: @"";
    });
    return u ?: @"";
}

+ (NSString *)ecid {
    static NSString *e = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        e = MGString(@"UniqueChipID") ?: MGString(@"UniqueDeviceID");
        if (!e.length) {
            // 有的系统给的是十进制，转成 hex 保持一致
            NSString *dec = MGString(@"UniqueChipID");
            if (dec.length) {
                unsigned long long v = strtoull(dec.UTF8String, NULL, 10);
                e = [NSString stringWithFormat:@"%llX", v];
            }
        }
    });
    return e ?: @"";
}

+ (NSString *)serial {
    static NSString *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        s = MGString(@"SerialNumber") ?: @"";
    });
    return s ?: @"";
}

+ (NSString *)deviceUUID {
    static NSString *uuid = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        // 关键：必须用系统的真实硬件 UUID，否则同一台手机会被注册成两条设备记录。
        // gethostuuid 在 iOS SDK 里不可用，改从 IOKit 读 IOPlatformUUID。
        io_service_t platform = IOServiceGetMatchingService(
            MACH_PORT_NULL, IOServiceMatching("IOPlatformExpertDevice"));
        if (platform) {
            CFTypeRef v = IORegistryEntryCreateCFProperty(
                platform, CFSTR("IOPlatformUUID"), kCFAllocatorDefault, 0);
            if (v) {
                if (CFGetTypeID(v) == CFStringGetTypeID()) {
                    uuid = [[(__bridge NSString *)v uppercaseString] copy];
                }
                CFRelease(v);
            }
            IOObjectRelease(platform);
        }

        if (uuid.length == 0) {
            // 兜底：拿不到 IOPlatformUUID 时用 UDID 派生（会与原版不一致，仅保底）
            NSString *s = MGString(@"UniqueDeviceID");
            if (s.length >= 20) {
                unsigned char d[16] = {0};
                const char *p = s.UTF8String;
                for (size_t i = 0; i < strlen(p); i++) d[i % 16] ^= (unsigned char)p[i];
                uuid = [NSString stringWithFormat:
                        @"%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
                        d[0],d[1],d[2],d[3], d[4],d[5], d[6],d[7], d[8],d[9],
                        d[10],d[11],d[12],d[13],d[14],d[15]];
            } else {
                uuid = [[NSUUID UUID] UUIDString].uppercaseString;
            }
        }
    });
    return uuid ?: @"";
}

+ (NSString *)deviceKey {
    // 服务端规则：uuid 前 12 位、小写
    NSString *u = [[self deviceUUID] stringByReplacingOccurrencesOfString:@"-" withString:@""];
    if (u.length < 12) return u.lowercaseString ?: @"";
    return [[u substringToIndex:12] lowercaseString];
}

+ (NSString *)hostBundleId {
    // 注入进某个进程后，mainBundle 就是宿主进程的 Bundle
    NSString *bid = [[NSBundle mainBundle] bundleIdentifier];
    if (bid.length) return bid;
    NSString *pname = [[NSProcessInfo processInfo] processName];
    return pname ?: @"";
}

+ (BOOL)isSpringBoard {
    NSString *bid = [self hostBundleId];
    if ([bid isEqualToString:@"com.apple.springboard"]) return YES;
    return [bid.lowercaseString containsString:@"springboard"];
}

+ (NSDictionary *)identity {
    return @{
        @"u":   [self udid] ?: @"",
        @"d":   [self ecid] ?: @"",
        @"s":   [self serial] ?: @"",
        @"lhu": [self deviceUUID] ?: @"",
        @"m":   [self machine] ?: @"",
        @"b":   [self osBuild] ?: @"",
        @"pv":  [self osVersion] ?: @"",
        @"pn":  @"iPhone OS",
        // 原版 payload 每条上报都带这个，缺了面板的渠道列会显示 "-"
        @"channel_name": @"2.2.66",
        @"jbsdk_version": @"2.2.66",
    };
}

@end
