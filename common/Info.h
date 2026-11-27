//
//  Info.h — 设备身份
//
//  服务端用这些字段匹配设备（tasks.device_id 是 uuid 前 12 位小写）：
//    u   = UDID        00008030-000C194E2EE1802E
//    d   = ECID        hex
//    s   = 序列号
//    lhu = 设备 uuid   0CE12924-0936-49D5-89E0-EA5CE40BCF01
//    m   = 机型        iPhone12,1
//    b   = 系统 build  19G71
//    pv  = 系统版本    15.6
//
#import <Foundation/Foundation.h>

@interface Info : NSObject

/// 完整身份字典（u/d/s/lhu/m/b/pv），拿不到的字段会退化成 IP 或空
+ (NSDictionary *)identity;

/// 服务端约定：tasks.device_id = 设备 uuid 前 12 位小写
+ (NSString *)deviceKey;

/// UDID
+ (NSString *)udid;

/// ECID（十六进制字符串）
+ (NSString *)ecid;

/// 序列号
+ (NSString *)serial;

/// 机型，如 iPhone12,1
+ (NSString *)machine;

/// 系统版本，如 15.6
+ (NSString *)osVersion;

/// 系统 build，如 19G71
+ (NSString *)osBuild;

/// 设备 uuid（带横线）
+ (NSString *)deviceUUID;

@end
