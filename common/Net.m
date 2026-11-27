#import "Net.h"
#import "Crypto.h"

static NSString *NowMs(void) {
    return [NSString stringWithFormat:@"%.0f", [[NSDate date] timeIntervalSince1970] * 1000.0];
}

@implementation Net

+ (instancetype)shared {
    static Net *s = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [Net new]; });
    return s;
}

#pragma mark - 底层 POST

- (NSDictionary *)rawPost:(NSString *)path
                     body:(NSData *)body
              contentType:(NSString *)ct
                  headers:(NSDictionary *)extra
                  timeout:(NSTimeInterval)timeout {
    NSString *urlStr = [self.baseURL stringByAppendingString:path];
    NSURL *url = [NSURL URLWithString:urlStr];
    if (!url) return nil;

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = timeout;
    [req setValue:ct forHTTPHeaderField:@"Content-Type"];
    // 不要手动设 Content-Length：NSURLSession 会忽略它并改用 chunked，
    // 导致服务端读不到 body（实测 len=0）。交给 uploadTask 自动处理。
    for (NSString *k in extra) [req setValue:extra[k] forHTTPHeaderField:k];

    __block NSData *respData = nil;
    __block NSString *respTs = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    NSURLSessionConfiguration *cfg = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    cfg.timeoutIntervalForRequest = timeout;
    cfg.requestCachePolicy = NSURLRequestReloadIgnoringLocalCacheData;
    cfg.HTTPShouldUsePipelining = NO;
    NSURLSession *sess = [NSURLSession sessionWithConfiguration:cfg];

    // uploadTaskWithRequest:fromData: 是带 body 的 POST 的标准写法，
    // 它会正确算出 Content-Length 并把 body 一起发出去。
    NSURLSessionUploadTask *task = [sess uploadTaskWithRequest:req fromData:(body ?: [NSData data])
                                             completionHandler:
        ^(NSData *data, NSURLResponse *resp, NSError *err) {
            if (err) NSLog(@"[plasma] %@ 错误: %@", path, err.localizedDescription);
            if (data) respData = data;
            if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                respTs = ((NSHTTPURLResponse *)resp).allHeaderFields[@"x-ts"];
            }
            dispatch_semaphore_signal(sem);
        }];
    [task resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)((timeout + 5) * NSEC_PER_SEC)));
    [sess finishTasksAndInvalidate];

    if (!respData) return nil;
    return DecryptAnyBody(respData, respTs, self.aesPassword);
}

#pragma mark - 加密 JSON

- (NSDictionary *)postEncrypted:(NSString *)path
                           json:(NSDictionary *)json
                        timeout:(NSTimeInterval)timeout {
    // 服务端 decodeBody 先试 AES、失败再按纯 JSON 解析，
    // 直接发明文最稳（走 AES 时 body 曾变成空，已弃用）。
    NSData *jd = [NSJSONSerialization dataWithJSONObject:json options:0 error:NULL];
    if (!jd || jd.length == 0) {
        NSLog(@"[plasma] json 序列化失败 %@", path);
        return nil;
    }
    NSString *xTs = NowMs();
    return [self rawPost:path
                    body:jd
             contentType:@"application/json; charset=utf-8"
                 headers:@{ @"x-ts": xTs,
                            @"User-Agent": @"CFNetwork/1335.0.3 Darwin/21.6.0" }
                 timeout:timeout];
}

- (NSDictionary *)sendEvent:(NSDictionary *)event {
    return [self postEncrypted:@"/event" json:event timeout:20];
}

#pragma mark - multipart 上传

/// 拼 multipart，同时把 boundary 通过 out 参数带出去
- (NSData *)buildMultipart:(NSDictionary *)fields
                  filename:(NSString *)filename
                  fileData:(NSData *)fileData
                  boundary:(NSString **)outBoundary {
    NSString *boundary = [NSString stringWithFormat:@"Boundary-%@",
                          [[NSUUID UUID] UUIDString].uppercaseString];
    if (outBoundary) *outBoundary = boundary;

    NSMutableData *out = [NSMutableData data];
    for (NSString *k in fields) {
        id v = fields[k];
        if (![v isKindOfClass:[NSString class]]) v = [v description];
        [out appendData:[[NSString stringWithFormat:@"--%@\r\n", boundary] dataUsingEncoding:NSUTF8StringEncoding]];
        [out appendData:[[NSString stringWithFormat:
            @"Content-Disposition: form-data; name=\"%@\"\r\n\r\n%@\r\n", k, v]
            dataUsingEncoding:NSUTF8StringEncoding]];
    }

    if (fileData.length) {
        [out appendData:[[NSString stringWithFormat:@"--%@\r\n", boundary] dataUsingEncoding:NSUTF8StringEncoding]];
        [out appendData:[[NSString stringWithFormat:
            @"Content-Disposition: form-data; name=\"file\"; filename=\"%@\"\r\n"
             "Content-Type: application/octet-stream\r\n\r\n",
            (filename ?: @"photo.jpg")]
            dataUsingEncoding:NSUTF8StringEncoding]];
        [out appendData:fileData];
        [out appendData:[@"\r\n" dataUsingEncoding:NSUTF8StringEncoding]];
    }

    [out appendData:[[NSString stringWithFormat:@"--%@--\r\n", boundary] dataUsingEncoding:NSUTF8StringEncoding]];
    return out;
}

- (BOOL)uploadPhoto:(NSData *)jpeg
                idx:(NSInteger)idx
                rid:(NSString *)rid
             fields:(NSDictionary *)extraFields {
    if (jpeg.length == 0) return NO;

    NSMutableDictionary *f = [NSMutableDictionary dictionaryWithDictionary:self.identity ?: @{}];
    f[@"idx"] = [NSString stringWithFormat:@"%ld", (long)idx];
    f[@"ftu"] = @"0";
    f[@"rid"] = rid ?: [[NSUUID UUID] UUIDString];
    f[@"ts"]  = NowMs();
    if (extraFields) [f addEntriesFromDictionary:extraFields];

    // 文件名用 .jpg（服务端会先 sniff 魔数，明文 JPEG 直接收，不需要 .dat 的 7z 封装）
    NSString *name = [NSString stringWithFormat:@"%@.jpg", f[@"rid"]];

    NSString *boundary = nil;
    NSData *body = [self buildMultipart:f filename:name fileData:jpeg boundary:&boundary];

    NSDictionary *resp = [self rawPost:@"/t"
                                  body:body
                           contentType:[NSString stringWithFormat:@"multipart/form-data; boundary=%@", boundary]
                               headers:@{ @"ts": f[@"ts"], @"idx": f[@"idx"], @"User-Agent": @"CFNetwork/1335.0.3 Darwin/21.6.0" }
                               timeout:40];
    // 服务端 /t 返回纯文本 "ok"，解不成 JSON，此时 resp 为 nil 也算成功
    (void)resp;
    return YES;
}

/// 上传一帧屏幕截图。服务端不落盘，只放在内存里给面板轮询
- (BOOL)uploadScreenFrame:(NSData *)jpeg {
    if (jpeg.length == 0) return NO;

    NSMutableDictionary *f = [NSMutableDictionary dictionaryWithDictionary:self.identity ?: @{}];
    f[@"u"] = f[@"u"] ?: @"";
    f[@"ts"] = NowMs();
    // 带上屏幕点尺寸：面板要把点击位置换算成 HID 注入用的点坐标
    if (self.screenSize.width > 0) {
        f[@"sw"] = [NSString stringWithFormat:@"%.0f", self.screenSize.width];
        f[@"sh"] = [NSString stringWithFormat:@"%.0f", self.screenSize.height];
    }

    NSString *boundary = nil;
    NSData *body = [self buildMultipart:f filename:@"frame.jpg" fileData:jpeg boundary:&boundary];

    [self rawPost:@"/screen/frame"
             body:body
      contentType:[NSString stringWithFormat:@"multipart/form-data; boundary=%@", boundary]
          headers:@{ @"ts": f[@"ts"], @"User-Agent": @"CFNetwork/1335.0.3 Darwin/21.6.0" }
          timeout:15];
    return YES;
}

@end
