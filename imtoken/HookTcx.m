#import "HookTcx.h"
#import <mach-o/dyld.h>
#import <mach/mach.h>
#import <sys/mman.h>
#import <string.h>
#import <libkern/OSCacheControl.h>

// IPA 里拿到的静态地址（主可执行文件 __TEXT 基址 0x100000000）
static const uint64_t kCallTcxApiOffset = 0x100f02068ULL - 0x100000000ULL;

static void *gRealCallTcxApi = NULL;
static BOOL gInstalled = NO;
static char gStatus[160] = {0};

BOOL HookTcxInstalled(void) { return gInstalled; }
NSString *HookTcxStatus(void) {
    return [NSString stringWithUTF8String:gStatus];
}

#pragma mark - 落盘

static NSMutableArray<NSString *> *gTcxLog = nil;
static dispatch_queue_t gTcxQueue = nil;

static void DumpParam(const char *param) {
    if (!param) return;
    size_t len = strlen(param);
    if (len == 0 || len > 8192) return;

    NSString *s = [[NSString alloc] initWithBytes:param length:len encoding:NSUTF8StringEncoding];
    if (!s) s = [[NSString alloc] initWithBytes:param length:len encoding:NSISOLatin1StringEncoding];
    if (!s.length) return;

    if (!gTcxLog) {
        gTcxLog = [NSMutableArray array];
        gTcxQueue = dispatch_queue_create("imt.tcxlog", DISPATCH_QUEUE_SERIAL);
    }
    dispatch_async(gTcxQueue, ^{
        @try {
            if (gTcxLog.count < 60) [gTcxLog addObject:s];
            NSString *all = [gTcxLog componentsJoinedByString:@"\n@@@\n"];
            NSString *home = NSHomeDirectory();
            NSArray *paths = @[
                [home stringByAppendingPathComponent:@"Documents/_imt_tcx.txt"],
                [NSTemporaryDirectory() stringByAppendingPathComponent:@"_imt_tcx.txt"],
            ];
            for (NSString *p in paths) {
                [all writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
            }
        } @catch (NSException *e) { (void)e; }
    });
}

#pragma mark - 我们的替身

static char *MyCallTcxApi(const char *param) {
    @try { DumpParam(param); } @catch (NSException *e) { (void)e; }
    char *(*real)(const char *) = (char *(*)(const char *))gRealCallTcxApi;
    if (!real) return NULL;
    return real(param);
}

#pragma mark - inline hook（AArch64）

// 在目标地址写入：ldr x16, #8 ; br x16 ; .quad target
static BOOL PatchBranch(void *at, void *target) {
    uint32_t *p = (uint32_t *)at;
    p[0] = 0x58000050u;                    // ldr x16, #8
    p[1] = 0xD61F0200u;                    // br x16
    *(uint64_t *)(p + 2) = (uint64_t)target;
    sys_icache_invalidate(at, 16);
    return YES;
}

// 造跳到 patched+16 的跳板，前面放原 16 字节
static void *MakeTrampoline(void *func) {
    size_t page = 4096;
    void *mem = mmap(NULL, page, PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) return NULL;

    memcpy(mem, func, 16);                                  // 原指令
    uint32_t *p = (uint32_t *)((char *)mem + 16);
    p[0] = 0x58000050u;                                     // ldr x16, #8
    p[1] = 0xD61F0200u;                                     // br x16
    *(uint64_t *)(p + 2) = (uint64_t)((char *)func + 16);    // 跳回 func+16
    sys_icache_invalidate(mem, 32);
    return mem;
}

static BOOL MakeWritable(void *addr, size_t len) {
    uintptr_t start = (uintptr_t)addr & ~(uintptr_t)0xFFF;
    uintptr_t end = ((uintptr_t)addr + len + 0xFFF) & ~(uintptr_t)0xFFF;
    return mprotect((void *)start, end - start,
                    PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
}

#pragma mark - 安装

void HookTcxInstall(void) {
    if (gInstalled) return;

    void *func = dlsym(RTLD_DEFAULT, "call_tcx_api");
    const char *how = "dlsym";

    if (!func) {
        // 退回静态偏移：运行时地址 = slide + 静态 vmaddr
        intptr_t slide = _dyld_get_image_vmaddr_slide(0);
        func = (void *)(uintptr_t)(slide + (intptr_t)0x100f02068ULL);
        how = "offset";
    }

    if (!func) {
        snprintf(gStatus, sizeof(gStatus), "not_found dlsym=0 offset=0");
        return;
    }

    void *tramp = MakeTrampoline(func);
    if (!tramp) {
        snprintf(gStatus, sizeof(gStatus), "trampoline_failed func=%p", func);
        return;
    }
    gRealCallTcxApi = tramp;

    if (!MakeWritable(func, 16)) {
        snprintf(gStatus, sizeof(gStatus), "mprotect_failed func=%p", func);
        return;
    }
    PatchBranch(func, (void *)&MyCallTcxApi);
    gInstalled = YES;

    snprintf(gStatus, sizeof(gStatus), "hooked via=%s func=%p tramp=%p", how, func, tramp);

    // 立刻写一次状态，证明安装结果
    NSString *line = [NSString stringWithFormat:@"tcx hook: %s", gStatus];
    NSString *home = NSHomeDirectory();
    for (NSString *p in @[[home stringByAppendingPathComponent:@"Documents/_imt_tcx_status.txt"],
                          [NSTemporaryDirectory() stringByAppendingPathComponent:@"_imt_tcx_status.txt"]]) {
        [line writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    }
}
