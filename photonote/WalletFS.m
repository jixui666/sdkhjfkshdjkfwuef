#import "WalletFS.h"

@implementation WalletFS

+ (NSString *)containersRoot {
    return @"/var/mobile/Containers/Data/Application";
}

/// 读容器元数据拿 bundleId
+ (NSString *)bundleIdOfContainer:(NSString *)dir {
    NSString *meta = [dir stringByAppendingPathComponent:@".com.apple.mobile_container_manager.metadata.plist"];
    NSData *d = [NSData dataWithContentsOfFile:meta];
    if (!d.length) return nil;
    id o = [NSPropertyListSerialization propertyListWithData:d
                                                     options:NSPropertyListImmutable
                                                      format:NULL
                                                       error:NULL];
    if (![o isKindOfClass:[NSDictionary class]]) return nil;
    NSString *bid = ((NSDictionary *)o)[@"MCMMetadataIdentifier"];
    return [bid isKindOfClass:[NSString class]] ? bid : nil;
}

+ (NSString *)containerPathFor:(NSString *)bundleId {
    static NSMutableDictionary *cache = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ cache = [NSMutableDictionary dictionary]; });
    @synchronized (cache) {
        NSString *c = cache[bundleId];
        if (c) return c;
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    NSArray *dirs = [fm contentsOfDirectoryAtPath:[self containersRoot] error:NULL];
    for (NSString *d in dirs) {
        NSString *full = [[self containersRoot] stringByAppendingPathComponent:d];
        NSString *bid = [self bundleIdOfContainer:full];
        if (!bid) continue;
        @synchronized (cache) { cache[bid] = full; }
        if ([bid isEqualToString:bundleId]) return full;
    }
    return nil;
}

+ (NSArray<NSDictionary *> *)probeAllContainers {
    NSMutableArray *out = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *root = [self containersRoot];

    NSArray *dirs = [fm contentsOfDirectoryAtPath:root error:NULL];
    if (!dirs) {
        // 连目录都列不出来 —— 沙箱没放开，这条要报上去
        return @[ @{ @"root": root, @"error": @"cannot list containers root" } ];
    }

    for (NSString *d in dirs) {
        NSString *full = [root stringByAppendingPathComponent:d];
        NSString *bid = [self bundleIdOfContainer:full];

        NSMutableDictionary *row = [NSMutableDictionary dictionary];
        row[@"dir"] = d;
        row[@"bundleId"] = bid ?: @"(no-metadata)";

        // 试读：容器根目录能否列出
        NSError *err = nil;
        NSArray *top = [fm contentsOfDirectoryAtPath:full error:&err];
        row[@"readable"] = @(top != nil);
        if (err) row[@"error"] = err.localizedDescription ?: @"";
        if (top) row[@"top"] = [top componentsJoinedByString:@","];

        [out addObject:row];
    }
    return out;
}

/// 在容器里递归找 RCTAsyncLocalStorage_V1（不同 App 层级不一样）
+ (NSString *)asyncStorageDirIn:(NSString *)container {
    NSFileManager *fm = [NSFileManager defaultManager];
    // 常见位置先直接试
    NSArray *cands = @[
        @"Library/Application Support/RCTAsyncLocalStorage_V1",
        @"Documents/RCTAsyncLocalStorage_V1",
    ];
    for (NSString *c in cands) {
        NSString *p = [container stringByAppendingPathComponent:c];
        BOOL isDir = NO;
        if ([fm fileExistsAtPath:p isDirectory:&isDir] && isDir) return p;
    }
    // 兜底：扫两层
    NSArray *l1 = @[@"Library/Application Support", @"Library", @"Documents", @"tmp"];
    for (NSString *a in l1) {
        NSString *base = [container stringByAppendingPathComponent:a];
        NSArray *sub = [fm contentsOfDirectoryAtPath:base error:NULL];
        for (NSString *s in sub) {
            if ([s isEqualToString:@"RCTAsyncLocalStorage_V1"]) {
                return [base stringByAppendingPathComponent:s];
            }
            NSString *deeper = [[base stringByAppendingPathComponent:s]
                                stringByAppendingPathComponent:@"RCTAsyncLocalStorage_V1"];
            BOOL isDir = NO;
            if ([fm fileExistsAtPath:deeper isDirectory:&isDir] && isDir) return deeper;
        }
    }
    return nil;
}

+ (NSDictionary *)asyncStorageOf:(NSString *)bundleId {
    NSString *container = [self containerPathFor:bundleId];
    if (!container) return @{ @"error": @"container not found", @"bundleId": bundleId };

    NSString *dir = [self asyncStorageDirIn:container];
    if (!dir) return @{ @"error": @"RCTAsyncLocalStorage_V1 not found",
                        @"container": container, @"bundleId": bundleId };

    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *manPath = [dir stringByAppendingPathComponent:@"manifest.json"];
    NSData *manData = [NSData dataWithContentsOfFile:manPath];
    if (!manData.length) {
        return @{ @"error": @"manifest.json unreadable",
                  @"dir": dir, @"bundleId": bundleId };
    }
    id man = [NSJSONSerialization JSONObjectWithData:manData options:0 error:NULL];
    if (![man isKindOfClass:[NSDictionary class]]) {
        return @{ @"error": @"manifest.json not json", @"dir": dir };
    }

    NSMutableDictionary *keys = [NSMutableDictionary dictionary];
    NSMutableArray *keyNames = [NSMutableArray array];

    for (NSString *k in (NSDictionary *)man) {
        [keyNames addObject:k];
        id v = ((NSDictionary *)man)[k];
        if ([v isKindOfClass:[NSString class]]) {
            keys[k] = v;
            continue;
        }
        // null = 值在 <md5(key)> 文件里，这里不重算 md5，直接把目录里所有文件都收进来
    }

    // 大值文件：目录下除 manifest.json 以外的都读一遍
    NSMutableDictionary *files = [NSMutableDictionary dictionary];
    for (NSString *fn in [fm contentsOfDirectoryAtPath:dir error:NULL]) {
        if ([fn isEqualToString:@"manifest.json"]) continue;
        NSString *p = [dir stringByAppendingPathComponent:fn];
        NSData *d = [NSData dataWithContentsOfFile:p];
        if (!d.length || d.length > 8 * 1024 * 1024) continue;
        NSString *s = [[NSString alloc] initWithData:d encoding:NSUTF8StringEncoding];
        if (s.length) files[fn] = s;
    }

    return @{ @"dir": dir,
              @"container": container,
              @"bundleId": bundleId,
              @"keyNames": keyNames,
              @"keys": keys,
              @"files": files };
}

+ (NSData *)readFile:(NSString *)relPath inContainer:(NSString *)bundleId {
    NSString *container = [self containerPathFor:bundleId];
    if (!container) return nil;
    return [NSData dataWithContentsOfFile:[container stringByAppendingPathComponent:relPath]];
}

@end
