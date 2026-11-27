//
//  Screen.h — 屏幕采集 + 触摸注入
//
//  采集：优先 UIGetScreenImage（整屏含状态栏），退回渲染主窗口图层
//  注入：IOHIDEvent 数字转换器事件（手指按下/移动/抬起），系统级有效
//
//  注意：IOHIDEvent 注入依赖进程权限。SpringBoard 里成功率高，
//  其他 daemon 大概率被沙盒拦（会返回 nil / 派发失败）。
//
#import <Foundation/Foundation.h>
#import <CoreGraphics/CoreGraphics.h>

@interface Screen : NSObject

/// 抓一帧 JPEG，失败返回 nil。quality 0~1
+ (NSData *)captureJPEG:(CGFloat)quality;

/// 最近一次采集失败的原因（成功时为空串）
+ (NSString *)lastCaptureError;

/// 当前屏幕像素尺寸（点），拿不到返回 CGSizeZero
+ (CGSize)screenSize;

/// 是否具备触摸注入能力（能拿到 HID client）
+ (BOOL)canInjectTouch;

/// 最近一次注入失败的原因
+ (NSString *)lastInjectError;

/// 单击（坐标是屏幕点坐标，原点左上）
+ (BOOL)tapAt:(CGPoint)pt;

/// 滑动
+ (BOOL)swipeFrom:(CGPoint)from to:(CGPoint)to duration:(NSTimeInterval)duration;

/// 长按
+ (BOOL)longPressAt:(CGPoint)pt duration:(NSTimeInterval)duration;

@end
