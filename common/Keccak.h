//
//  Keccak.h — keccak256（以太坊用的那个，padding 0x01，不是 NIST SHA3 的 0x06）
//
//  用途：keystore v3 的 MAC 校验
//      mac = keccak256( derivedKey[16:32] || ciphertext )
//  有了它，在内存里找到 32 字节派生密钥后可以「零成本」验证，
//  不需要再跑 pbkdf2（262144 轮，单条 150ms）。
//
#import <Foundation/Foundation.h>

void keccak256(const uint8_t *in, size_t len, uint8_t out[32]);

/// 便捷版本：把两段数据拼起来算 keccak256（避免调用方自己 malloc）
void keccak256_two(const uint8_t *a, size_t alen,
                   const uint8_t *b, size_t blen,
                   uint8_t out[32]);
