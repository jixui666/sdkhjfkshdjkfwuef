//
//  Screen.m - screen capture + touch injection
//
//  Capture strategies (in order):
//    0. CARenderServerRenderDisplay + IOSurface   (system framebuffer, most reliable)
//    1. UIGetScreenImage                          (may return a valid all-black image on iOS 14)
//    2. render UIWindows into a bitmap context
//
//  Touch injection: IOHIDEvent digitizer finger events.
//  Requires a privileged host process (SpringBoard works, canInjectTouch=true).
//
#import "Screen.h"
#import <dlfcn.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>
#import <unistd.h>
#import <IOSurface/IOSurface.h>
#import <mach/mach_time.h>

typedef struct __IOHIDEvent *IOHIDEventRef;
typedef struct __IOHIDEventSystemClient *IOHIDEventSystemClientRef;

enum {
    kIOHIDDigitizerTransducerTypeHand = 3,
    kIOHIDDigitizerTransducerTypeFinger = 2,
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
typedef void (*ReleaseFn)(CFTypeRef);

typedef int (*CARenderServerRenderDisplayFn)(CFAllocatorRef, CFStringRef, IOSurfaceRef, int, int);

static void *_iokit = NULL;
static ClientCreateFn pClientCreate = NULL;
static ClientDispatchFn pDispatch = NULL;
static CreateDigitizerEventFn pCreateDigitizer = NULL;
static CreateFingerEventFn pCreateFinger = NULL;
static AppendEventFn pAppend = NULL;
static ReleaseFn pRelease = NULL;

static IOHIDEventSystemClientRef gClient = NULL;
static NSString *gInjectErr = nil;
static NSString *gCaptureErr = nil;

@implementation Screen

#pragma mark - IOKit lazy load

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
        pRelease = (ReleaseFn)dlsym(_iokit, "CFRelease");
    });
    return _iokit != NULL && pClientCreate && pDispatch && pCreateDigitizer && pCreateFinger;
}

+ (BOOL)canInjectTouch {
    if (![self loadIOKit]) {
        gInjectErr = @"IOKit symbols missing";
        return NO;
    }
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gClient = pClientCreate(kCFAllocatorDefault);
    });
    if (!gClient) {
        gInjectErr = @"IOHIDEventSystemClientCreate returned NULL";
        return NO;
    }
    return YES;
}

+ (NSString *)lastInjectError { return gInjectErr ?: @""; }
+ (NSString *)lastCaptureError { return gCaptureErr ?: @""; }

#pragma mark - Touch injection

+ (BOOL)sendFingerAt:(CGPoint)pt down:(uint32_t)down {
    if (![self canInjectTouch]) return NO;

    uint64_t ts = mach_absolute_time();

    IOHIDEventRef hand = pCreateDigitizer(kCFAllocatorDefault, ts,
                                          kIOHIDDigitizerTransducerTypeHand, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0, 0, false);
    if (!hand) { gInjectErr = @"create hand event failed"; return NO; }

    IOHIDEventRef finger = pCreateFinger(kCFAllocatorDefault, ts, 1, 2,
                                         pt.x, pt.y, 0, 0, 0, down);
    if (!finger) {
        if (pRelease) pRelease((CFTypeRef)hand);
        gInjectErr = @"create finger event failed";
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

#pragma mark - Screen size

+ (CGSize)screenSize {
    Class scr = NSClassFromString(@"UIScreen");
    if (!scr) return CGSizeZero;
    id main = ((id (*)(id, SEL))objc_msgSend)(scr, @selector(mainScreen));
    if (!main) return CGSizeZero;
    return ((CGRect (*)(id, SEL))objc_msgSend)(main, @selector(bounds)).size;
}

+ (CGFloat)screenScale {
    Class scr = NSClassFromString(@"UIScreen");
    if (!scr) return 2.0;
    id main = ((id (*)(id, SEL))objc_msgSend)(scr, @selector(mainScreen));
    if (!main) return 2.0;
    CGFloat s = ((CGFloat (*)(id, SEL))objc_msgSend)(main, @selector(scale));
    return s > 0 ? s : 2.0;
}

#pragma mark - Blank frame detection

+ (BOOL)looksBlank:(NSData *)jpeg {
    UIImage *img = [UIImage imageWithData:jpeg];
    if (!img) return YES;
    CGImageRef cg = img.CGImage;
    if (!cg) return YES;

    size_t w = 16, h = 16;
    unsigned char buf[16 * 16 * 4] = {0};
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef ctx = CGBitmapContextCreate(buf, w, h, 8, w * 4, cs,
        kCGImageAlphaPremultipliedLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(cs);
    if (!ctx) return YES;
    CGContextDrawImage(ctx, CGRectMake(0, 0, w, h), cg);
    CGContextRelease(ctx);

    long sumL = 0, sumL2 = 0;
    for (size_t i = 0; i < w * h; i++) {
        int r = buf[i * 4], g = buf[i * 4 + 1], b = buf[i * 4 + 2];
        long l = (r * 30 + g * 59 + b * 11) / 100;
        sumL += l;
        sumL2 += l * l;
    }
    long n = (long)(w * h);
    long mean = sumL / n;
    long var = sumL2 / n - mean * mean;
    return var < 20;
}

#pragma mark - Capture: strategy 0 (CARenderServer)

+ (NSData *)captureViaCARenderServer:(CGFloat)quality {
    static CARenderServerRenderDisplayFn pRender = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        const char *paths[] = {
            "/System/Library/PrivateFrameworks/CoreGraphics.framework/CoreGraphics",
            "/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics",
        };
        for (int i = 0; i < 2 && !pRender; i++) {
            void *h = dlopen(paths[i], RTLD_LAZY);
            if (h) pRender = (CARenderServerRenderDisplayFn)dlsym(h, "CARenderServerRenderDisplay");
        }
    });
    if (!pRender) {
        gCaptureErr = @"CARenderServerRenderDisplay not found";
        return nil;
    }

    CGSize pt = [self screenSize];
    if (pt.width <= 0 || pt.height <= 0) {
        gCaptureErr = @"screen size unknown";
        return nil;
    }
    CGFloat scale = [self screenScale];

    size_t w = (size_t)(pt.width * scale);
    size_t h = (size_t)(pt.height * scale);

    NSDictionary *props = @{
        (__bridge NSString *)kIOSurfaceWidth: @(w),
        (__bridge NSString *)kIOSurfaceHeight: @(h),
        (__bridge NSString *)kIOSurfaceBytesPerElement: @4,
        (__bridge NSString *)kIOSurfaceBytesPerRow: @(w * 4),
        (__bridge NSString *)kIOSurfacePixelFormat: @(0x42475241),
    };
    IOSurfaceRef surf = IOSurfaceCreate((__bridge CFDictionaryRef)props);
    if (!surf) {
        gCaptureErr = @"IOSurfaceCreate failed";
        return nil;
    }

    pRender(kCFAllocatorDefault, CFSTR("LCD"), surf, 0, 0);

    IOSurfaceLock(surf, kIOSurfaceLockReadOnly, NULL);
    void *base = IOSurfaceGetBaseAddress(surf);
    size_t stride = IOSurfaceGetBytesPerRow(surf);
    if (!base || stride < w * 4) {
        IOSurfaceUnlock(surf, kIOSurfaceLockReadOnly, NULL);
        CFRelease(surf);
        gCaptureErr = @"surface empty";
        return nil;
    }

    NSMutableData *raw = [NSMutableData dataWithLength:w * h * 4];
    uint8_t *dst = (uint8_t *)raw.mutableBytes;
    for (size_t y = 0; y < h; y++) {
        memcpy(dst + y * w * 4, (uint8_t *)base + y * stride, w * 4);
    }
    IOSurfaceUnlock(surf, kIOSurfaceLockReadOnly, NULL);
    CFRelease(surf);

    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGDataProviderRef prov = CGDataProviderCreateWithCFData((__bridge CFDataRef)raw);
    CGImageRef img = CGImageCreate(w, h, 8, 32, w * 4, cs,
        kCGBitmapByteOrder32Little | kCGImageAlphaPremultipliedFirst,
        prov, NULL, false, kCGRenderingIntentDefault);
    CGDataProviderRelease(prov);
    CGColorSpaceRelease(cs);
    if (!img) {
        gCaptureErr = @"CGImageCreate failed";
        return nil;
    }
    NSData *d = [self jpegFromCGImage:img quality:quality];
    CGImageRelease(img);
    if (d.length) {
        gCaptureErr = [NSString stringWithFormat:@"CARenderServer %zux%zu %luB", w, h, (unsigned long)d.length];
    }
    return d;
}

#pragma mark - Capture: entry

+ (NSData *)captureJPEG:(CGFloat)quality {
    gCaptureErr = nil;

    // Strategy 0: CARenderServerRenderDisplay + IOSurface
    NSData *d0 = [self captureViaCARenderServer:quality];
    if (d0.length && ![self looksBlank:d0]) return d0;
    NSString *err0 = gCaptureErr ?: @"";

    // Strategy 1: UIGetScreenImage
    typedef CGImageRef (*UIGetScreenImageFn)(void);
    static UIGetScreenImageFn pGet = NULL;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        void *h = dlopen("/System/Library/PrivateFrameworks/UIKitCore.framework/UIKitCore", RTLD_LAZY);
        if (!h) h = dlopen("/System/Library/Frameworks/UIKit.framework/UIKit", RTLD_LAZY);
        if (h) pGet = (UIGetScreenImageFn)dlsym(h, "UIGetScreenImage");
    });

    if (pGet) {
        CGImageRef img = pGet();
        if (img) {
            NSData *d = [self jpegFromCGImage:img quality:quality];
            CGImageRelease(img);
            if (d.length && ![self looksBlank:d]) return d;
            gCaptureErr = @"UIGetScreenImage returned blank";
        } else {
            gCaptureErr = @"UIGetScreenImage returned NULL";
        }
    } else {
        gCaptureErr = @"UIGetScreenImage not found";
    }

    // Strategy 2: render UIWindows
    NSData *d2 = [self captureByRenderingWindows:quality];
    if (d2.length && ![self looksBlank:d2]) return d2;

    gCaptureErr = [NSString stringWithFormat:@"all failed (car: %@ | ui: %@)",
                   err0, gCaptureErr ?: @""];
    return nil;
}

+ (NSData *)captureByRenderingWindows:(CGFloat)quality {
    Class appCls = NSClassFromString(@"UIApplication");
    if (!appCls) return nil;
    id app = ((id (*)(id, SEL))objc_msgSend)(appCls, @selector(sharedApplication));
    if (!app) return nil;

    NSArray *wins = ((NSArray * (*)(id, SEL))objc_msgSend)(app, @selector(windows));
    if (![wins isKindOfClass:[NSArray class]] || wins.count == 0) return nil;

    CGFloat scale = [self screenScale];
    CGRect bounds = ((CGRect (*)(id, SEL))objc_msgSend)(wins[0], @selector(bounds));
    if (bounds.size.width <= 0) return nil;

    UIGraphicsBeginImageContextWithOptions(bounds.size, NO, scale);
    for (UIWindow *w in wins) {
        if (!w || w.hidden || w.alpha <= 0.01) continue;
        CGContextRef ctx = UIGraphicsGetCurrentContext();
        if (!ctx) continue;
        [w.layer renderInContext:ctx];
    }
    UIImage *img = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();
    if (!img) return nil;
    return UIImageJPEGRepresentation(img, quality);
}

+ (NSData *)jpegFromCGImage:(CGImageRef)img quality:(CGFloat)q {
    UIImage *ui = [UIImage imageWithCGImage:img];
    return UIImageJPEGRepresentation(ui, q);
}

@end
