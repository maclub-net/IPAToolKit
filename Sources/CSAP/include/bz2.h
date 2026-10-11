#ifndef CSAP_BZ2_H
#define CSAP_BZ2_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// 解压 bzip2 数据
// compressed: bzip2 压缩数据（必须以 BZh 开头）
// compressed_len: 压缩数据长度
// out_output: 输出缓冲区指针（调用者负责 free）
// out_output_len: 输出长度
// 返回 0 成功，非 0 失败
int csap_bz2_decompress(const uint8_t* compressed, size_t compressed_len,
                        uint8_t** out_output, size_t* out_output_len);

#ifdef __cplusplus
}
#endif

#endif // CSAP_BZ2_H
