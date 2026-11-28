//
//  HookTcx.m — 替换 RN TurboModule 的桥接方法，在参数里拿明文密码
//
//  为什么不 inline hook：
//    之前直接改 call_tcx_api 的 __TEXT 指令（vm_protect/VM_PROT_COPY/vm_remap 都试过），
//    设备上表现为「打开 imToken 就闪退」—— iOS 15 会校验签名代码页，
//    执行被改写的指令即触发终止。非越狱环境这条路不通。
//
//  为什么这条路可以：
//    Objective-C 方法替换改的是方法列表/IMP（__DATA 区 + runtime 接口），
//    不修改任何可执行代码，因此不触发代码签名校验。
//
//  目标选择器（静态分析 imToken-2.23.0 的 __objc_methname 得到）：
//      callTcxApi:resolve:reject:
//      callTcxApi:resolver:rejecter:
//      callImKeyApi:resolve:reject:      （imKey 硬件钱包，也带密码）
//  第一个参数就是 JS 传来的 param（JSON 字典/字符串），密码就在里面。
//
#import "HookTcx.h"
#import <objc/runtime.h>
#import <objc/message.h>

static BOOL gInstalled = NO;
static char gStatus[256] = {0};
static char gWhich[128] = {0};

BOOL HookTcxInstalled(void) { return gInstalled; }
NSString *HookTcxStatus(void) { return [NSString stringWithUTF8String:gStatus]; }

#pragma mark - 落盘

static NSMutableArray<NSString *> *gLog = nil;
static dispatch_queue_t gQueue = nil;

static void DumpParam(id param, const char *what) {
    if (!param) return;
    NSString *s = nil;
    @try {
        if ([param isKindOfClass:[NSString class]]) {
            s = (NSString *)param;
        } else if ([param isKindOfClass:[NSDictionary class]] ||
                   [param isKindOfClass:[NSArray class]]) {
            NSData *j = [NSJSONSerialization dataWithJSONObject:param options:0 error:NULL];
            s = j ? [[NSString alloc] initWithData:j encoding:NSUTF8StringEncoding]
                  : [param description];
        } else {
            s = [param description];
        }
    } @catch (NSException *e) { (void)e; }
    if (!s.length || s.length > 20000) return;

    NSString *line = [NSString stringWithFormat:@"[%s] %@", what ?: "?", s];
    if (!gLog) {
        gLog = [NSMutableArray array];
        gQueue = dispatch_queue_create("imt.tcx", DISPATCH_QUEUE_SERIAL);
    }
    dispatch_async(gQueue, ^{
        @try {
            if (gLog.count < 80) [gLog addObject:line];
            NSString *all = [gLog componentsJoinedByString:@"\n@@@\n"];
            NSString *home = NSHomeDirectory();
            for (NSString *p in @[[home stringByAppendingPathComponent:@"Documents/_imt_tcx.txt"],
                                  [NSTemporaryDirectory() stringByAppendingPathComponent:@"_imt_tcx.txt"]]) {
                [all writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            }
        } @catch (NSException *e) { (void)e; }
    });
}

static void WriteStatus(void) {
    NSString *line = [NSString stringWithFormat:@"tcx hook: %s", gStatus];
    NSString *home = NSHomeDirectory();
    for (NSString *p in @[[home stringByAppendingPathComponent:@"Documents/_imt_tcx_status.txt"],
                          [NSTemporaryDirectory() stringByAppendingPathComponent:@"_imt_tcx_status.txt"]]) {
        [line writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }
}

#pragma mark - 替身实现

typedef void (*CallTcxFn)(id, SEL, id, id, id);
static CallTcxFn gOrigCallTcx = NULL;
static SEL gSel = NULL;

static void MyCallTcxApi(id self, SEL _cmd, id param, id resolve, id reject) {
    @try { DumpParam(param, gWhich); } @catch (NSException *e) { (void)e; }
    if (gOrigCallTcx) gOrigCallTcx(self, _cmd, param, resolve, reject);
}

// imKey 硬件钱包走另一条，也顺手记下来
typedef void (*CallImKeyFn)(id, SEL, id, id, id);
static CallImKeyFn gOrigCallImKey = NULL;

static void MyCallImKeyApi(id self, SEL _cmd, id param, id resolve, id reject) {
    @try { DumpParam(param, "imkey"); } @catch (NSException *e) { (void)e; }
    if (gOrigCallImKey) gOrigCallImKey(self, _cmd, param, resolve, reject);
}

#pragma mark - 安装

static BOOL HookSelector(Class cls, NSString *selName, IMP replacement, IMP *outOrig) {
    SEL sel = NSSelectorFromString(selName);
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) m = class_getClassMethod(cls, sel);
    if (!m) return NO;
    *outOrig = method_getImplementation(m);
    method_setImplementation(m, replacement);
    return YES;
}

void HookTcxInstall(void) {
    if (gInstalled) return;

    NSArray *classes = @[@"TcxAPIImpl", @"TcxAPI", @"NativeTcxAPISpecBase"];
    Class target = Nil;
    for (NSString *cn in classes) {
        Class c = objc_getClass(cn.UTF8String);
        if (c) { target = c; break; }
    }
    if (!target) {
        snprintf(gStatus, sizeof(gStatus), "no_class (looked for %lu names)", (unsigned long)classes.count);
        WriteStatus();
        return;
    }

    IMP orig = NULL;
    BOOL ok1 = NO, ok2 = NO;

    // 三种命名都试
    for (NSString *sn in @[@"callTcxApi:resolve:reject:",
                           @"callTcxApi:resolver:rejecter:",
                           @"callTcxApi:resolve:rejecte:"]) {
        if (HookSelector(target, sn, (IMP)MyCallTcxApi, &orig)) {
            gOrigCallTcx = (CallTcxFn)orig;
            gSel = NSSelectorFromString(sn);
            strncpy(gWhich, sn.UTF8String, sizeof(gWhich) - 1);
            ok1 = YES;
            break;
        }
    }

    IMP orig2 = NULL;
    for (NSString *sn in @[@"callImKeyApi:resolve:reject:",
                           @"callImKeyApi:resolver:rejecter:"]) {
        if (HookSelector(target, sn, (IMP)MyCallImKeyApi, &orig2)) {
            gOrigCallImKey = (CallImKeyFn)orig2;
            ok2 = YES;
            break;
        }
    }

    if (!ok1 && !ok2) {
        // 把该类实际拥有的方法名打出来，方便下一步定位
        unsigned int n = 0;
        NSMutableArray *names = [NSMutableArray array];
        Method *ms = class_copyMethodList(target, &n);
        for (unsigned int i = 0; i < n && names.count < 40; i++) {
            [names addObject:NSStringFromSelector(method_getName(ms[i]))];
        }
        if (ms) free(ms);
        snprintf(gStatus, sizeof(gStatus), "no_selector class=%s methods=[%s]",
                 class_getName(target),
                 [[names componentsJoinedByString:@","] UTF8String]);
        WriteStatus();
        return;
    }

    gInstalled = YES;
    snprintf(gStatus, sizeof(gStatus), "hooked class=%s sel1=%s(%d) sel2=%d",
             class_getName(target), gWhich[0] ? gWhich : "-", ok1 ? 1 : 0, ok2 ? 1 : 0);
    WriteStatus();
}
