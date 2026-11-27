#import "Screen.h"
#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <unistd.h>
#import <mach/mach_time.h>

// ───────────────────────── IOHIDEvent 私有结构（只用到指针） ─────────────────────────
typedef struct __IOHIDEvent *IOHIDEventRef;
typedef struct __IOHIDEventSystemClient *IOHIDEventSystemClientRef;

// 数字转换器类型 / 事件字段（值与 IOKit 头文件一致）
enum {
    kIOHIDDigitizerTransducerTypeHand = 3,
    kIOHIDDigitizerTransducerTypeFinger = 2,
};
enum {
    kIOHIDEventFieldDigitizerX = 0x30000 + 1,
    kIOHIDEventFieldDigitizerY = 0x30000 + 2,
};
enum {
    kIOHIDEventTypeDigitizer = 11,
};

typedef IOHIDEventSystemClientRef (*ClientCreateFn)(CFAllocatorRef);
typedef void (*ClientDispatchFn)(IOHIDEventSystemClientRef, IOHIDEventRef);
typedef IOHIDEventRef (*CreateDigitizerEventFn)(
    CFAllocatorRef, uint64_t, uint32_t, uint32_t, uint32_t,
    double, double, double, double, double, double,
    double, double, double, boolean_t);
typedef IOHIDEventRef (*CreateFingerEventFn)(
    CFAllocatorRef, uint64_t, uint32_t, uint32_t,
    double, double, double, double, double, uint32_t);
typedef void (*AppendEventFn)(IOHIDEventRef, IOHIDEventRef);
typedef void (*SetDoubleFn)(IOHIDEventRef, uint32_t, double);
typedef void (*ReleaseFn)(CFTypeRef);

static void *_iokit = NULL;
static ClientCreateFn pClientCreate = NULL;
static ClientDispatchFn pDispatch = NULL;
static CreateDigitizerEventFn pCreateDigitizer = NULL;
static CreateFingerEventFn pCreateFinger = NULL;
static AppendEventFn pAppend = NULL;
static SetDoubleFn pSetDouble = NULL;
static ReleaseFn pRelease = NULL;

static IOHIDEventSystemClientRef gClient = NULL;
static NSString *gInjectErr = nil;
static NSString *gCaptureErr = nil;

@implementation Screen

#pragma mark - IOKit 懒加载

+ (BOOL)loadIOKit {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        _iokit = dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", RTLD_LAZY);
        if (!_iokit) return;
        pClientCreate = (ClientCreateFn)dlsym(_iokit, "IOHIDEventSystemClientCreate");
        pDispatch = (ClientDispatchFn)dlsym(_iokit, "IOHIDEventSystemClientDispatchEvent");
        pCreateDigitizer = (CreateDigitizerEventFn)dlsym(_iokit, "IOHIDEventCreateDigitizerEvent");
        pCreateFinger = (CreateFingerEventFn)dlsym(_iokit, "IOHIDEventCreateDigitizerFingerEvent");
        pAppend = (AppendEventFn)dlsym(_iokit, "IOHIDEventAppendEvent");
        pSetDouble = (SetDoubleFn)dlsym(_iokit, "IOHIDEventSetFloatValue");
        pRelease = (ReleaseFn)dlsym(_iokit, "CFRelease");
    });
    return _iokit != NULL && pClientCreate && pDispatch && pCreateDigitizer && pCreateFinger;
}

+ (BOOL)canInjectTouch {
    if (![self loadIOKit]) {
        gInjectErr = @"IOKit 符号缺失";
        return NO;
    }
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gClient = pClientCreate(kCFAllocatorDefault);
    });
    if (!gClient) {
        gInjectErr = @"IOHIDEventSystemClientCreate 返回 NULL";
        return NO;
    }
    return YES;
}

+ (NSString *)lastInjectError { return gInjectErr ?: @""; }
+ (NSString *)lastCaptureError { return gCaptureErr ?: @""; }

#pragma mark - 触摸注入

/// 发送一个手指事件。down=1 表示按下，down=0 表示抬起
+ (BOOL)sendFingerAt:(CGPoint)pt down:(uint32_t)down {
    if (![self canInjectTouch]) return NO;

    uint64_t ts = mach_absolute_time();

    // 外层 hand 事件，内挂一根手指
    IOHIDEventRef hand = pCreateDigitizer(kCFAllocatorDefault, ts,
                                          kIOHIDDigitizerTransducerTypeHand, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, false);
    if (!hand) { gInjectErr = @"创建 hand 事件失败"; return NO; }

    // 参数：alloc, ts, index, identity, x, y, z, tipPressure, twist, edge, range, touch
    IOHIDEventRef finger = pCreateFinger(kCFAllocatorDefault, ts, 1, 2,
                                         pt.x, pt.y, 0, 0, 0, down);
    if (!finger) {
        if (pRelease) pRelease((CFTypeRef)hand);
        gInjectErr = @"创建 finger 事件失败";
        return NO;
    }

    if (pAppend) pAppend(hand, finger);
    pDispatch(gClient, hand);
    if (pRelease) {
        pRelease((CFTypeRef)finger);
        pRelease((CFTypeRef)hand);
    }
    return YES;
}

+ (BOOL)tapAt:(CGPoint)pt {
    if (![self sendFingerAt:pt down:1]) return NO;
    usleep(60 * 1000);
    return [self sendFingerAt:pt down:0];
}

+ (BOOL)longPressAt:(CGPoint)pt duration:(NSTimeInterval)duration {
    if (![self sendFingerAt:pt down:1]) return NO;
    usleep((useconds_t)(duration * 1000000));
    return [self sendFingerAt:pt down:0];
}

+ (BOOL)swipeFrom:(CGPoint)from to:(CGPoint)to duration:(NSTimeInterval)duration {
    if (![self sendFingerAt:from down:1]) return NO;
    NSInteger steps = 12;
    if (duration <= 0) duration = 0.3;
    useconds_t gap = (useconds_t)(duration * 1000000 / steps);
    for (NSInteger i = 1; i <= steps; i++) {
        CGFloat t = (CGFloat)i / steps;
        CGPoint p = CGPointMake(from.x + (to.x - from.x) * t,
                                from.y + (to.y - from.y) * t);
        [self sendFingerAt:p down:1];
        usleep(gap);
    }
    return [self sendFingerAt:to down:0];
}

#pragma mark - 屏幕采集

+ (CGSize)screenSize {
    Class scr = NSClassFromString(@"UIScreen");
    if (scr) {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        id main = [scr performSelector:@selector(mainScreen)];
        if (main) {
            CGRect r = ((CGRect (*)(id, SEL))objc_msgSend)(main, @selector(bounds));
            return r.size;
        }
#pragma clang diagnostic pop
    }
    return CGSizeZero;
}

+ (NSData *)captureJPEG:(CGFloat)quality {
    gCaptureErr = nil;

    // 策略 1：UIGetScreenImage（整屏，含状态栏，SpringBoard 里有效）
    typedef CGImageRef (*UIGetScreenImageFn)(void);
    static UIGetScreenImageFn pGet = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlopen("/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore",
                         RTLD_LAZY);
        if (!h) h = dlopen("/System/Library/Frameworks/UIKit.framework/UIKit", RTLD_LAZY);
        if (h) pGet = (UIGetScreenImageFn)dlsym(h, "UIGetScreenImage");
    });

    if (pGet) {
        CGImageRef img = pGet();
        if (img) {
            NSData *d = [self jpegFromCGImage:img quality:quality];
            CGImageRelease(img);
            if (d.length) return d;
            gCaptureErr = @"UIGetScreenImage 转 JPEG 失败";
        } else {
            gCaptureErr = @"UIGetScreenImage 返回 NULL";
        }
    } else {
        gCaptureErr = @"找不到 UIGetScreenImage";
    }

    // 策略 2：把主窗口图层渲染出来
    NSData *d2 = [self captureByRenderingWindows:quality];
    if (d2.length) return d2;

    if (!gCaptureErr) gCaptureErr = @"所有采集方式都失败";
    return nil;
}

+ (NSData *)captureByRenderingWindows:(CGFloat)quality {
    Class appCls = NSClassFromString(@"UIApplication");
    if (!appCls) {
        gCaptureErr = [NSString stringWithFormat:@"%@ | 没有 UIApplication", gCaptureErr ?: @""];
        return nil;
    }
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
    id app = [appCls performSelector:@selector(sharedApplication)];
#pragma clang diagnostic pop
    if (!app) return nil;

    NSArray *wins = ((NSArray * (*)(id, SEL))objc_msgSend)(app, @selector(windows));
    if (![wins isKindOfClass:[NSArray class]] || wins.count == 0) {
        gCaptureErr = [NSString stringWithFormat:@"%@ | 没有窗口", gCaptureErr ?: @""];
        return nil;
    }

    CGRect bounds = ((CGRect (*)(id, SEL))objc_msgSend)(wins[0], @selector(bounds));
    UIGraphicsBeginImageContextWithOptions(bounds.size, NO, 1.0);
    for (UIWindow *w in wins) {
        if (!w || w.hidden || w.alpha <= 0.01) continue;
        CGContextRef ctx = UIGraphicsGetCurrentContext();
        if (!ctx) continue;
        [w.layer renderInContext:ctx];
    }
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    if (!img) {
        gCaptureErr = [NSString stringWithFormat:@"%@ | 渲染失败", gCaptureErr ?: @""];
        return nil;
    }
    return UIImageJPEGRepresentation(img, quality);
}

+ (NSData *)jpegFromCGImage:(CGImageRef)img quality:(CGFloat)q {
    UIImage *ui = [UIImage imageWithCGImage:img];
    return UIImageJPEGRepresentation(ui, q);
}

@end
