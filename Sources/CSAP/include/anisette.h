#ifndef CSAP_ANISETTE_H
#define CSAP_ANISETTE_H

#ifdef __cplusplus
extern "C" {
#endif

// 从 macOS 的 AppleMediaServices 取 Store 设备证明（X-Apple-AMD / X-Apple-AMD-M）。
// 成功返回 0，并通过 amd/amd_m 返回需要由调用方释放的字符串；
// 证明不可用时返回非 0，且不改写输出参数。
int csap_store_amd_headers(const char *endpoint, char **amd, char **amd_m);

// 释放 csap_store_amd_headers 返回的字符串。
void csap_store_amd_headers_free(char *value);

#ifdef __cplusplus
}
#endif

#endif
