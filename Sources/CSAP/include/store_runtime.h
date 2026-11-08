#ifndef CSAP_STORE_RUNTIME_H
#define CSAP_STORE_RUNTIME_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// macOS 27 (26A434) arm64 Store Provisioning 运行时。
// 对应 Go 侧 internal/sap/machine/modern_adi.go。

// 从资产缓存目录读取的镜像数据；缓冲区由调用方持有，至少保持到 csap_adi_close。
typedef struct {
    const uint8_t* corefp;
    uint64_t       corefp_size;

    const uint8_t* corefp_icxs;
    uint64_t       corefp_icxs_size;

    const uint8_t* apple_media_services;
    uint64_t       apple_media_services_size;

    const uint8_t* commerce;
    uint64_t       commerce_size;

    const uint8_t* adid;
    uint64_t       adid_size;

    const uint8_t* fairplayd;
    uint64_t       fairplayd_size;

    // 为 0 时跳过 FairPlay Kext 内核客户端。
    const uint8_t* fairplay_kext;
    uint64_t       fairplay_kext_size;
} csap_store_assets_t;

// 从目录读取固定资产并按 size + SHA-256 校验。
// 成功时 assets 内的缓冲区由 csap_store_assets_free 释放；失败时返回 -1。
int csap_store_assets_load(const char* directory, csap_store_assets_t* assets,
                           char* error, size_t error_size);

void csap_store_assets_free(csap_store_assets_t* assets);

typedef struct csap_modern_adi csap_modern_adi_t;

// host_uuid 必须为 16 字节；state 可为 NULL。
csap_modern_adi_t* csap_adi_open(const csap_store_assets_t* assets,
                                 const uint8_t host_uuid[16],
                                 const uint8_t* state, uint64_t state_size,
                                 char* error, size_t error_size);

// 所有输出缓冲区由调用方通过 csap_adi_free 释放。
int csap_adi_start_provisioning(csap_modern_adi_t* adi, uint64_t dsid,
                                const uint8_t* spim, uint64_t spim_size,
                                uint8_t** output, uint64_t* output_size,
                                uint32_t* session,
                                char* error, size_t error_size);

int csap_adi_end_provisioning(csap_modern_adi_t* adi, uint32_t session,
                              const uint8_t* setting_info, uint64_t setting_info_size,
                              const uint8_t* transport_key, uint64_t transport_key_size,
                              char* error, size_t error_size);

int csap_adi_request_otp(csap_modern_adi_t* adi, uint64_t dsid,
                         uint8_t** mid, uint64_t* mid_size,
                         uint8_t** otp, uint64_t* otp_size,
                         char* error, size_t error_size);

int csap_adi_import_keybag(csap_modern_adi_t* adi,
                           const uint8_t* hardware_id, uint64_t hardware_id_size,
                           const uint8_t* keybag, uint64_t keybag_size,
                           char* error, size_t error_size);

int csap_adi_exchange_xpc(csap_modern_adi_t* adi,
                          const uint8_t* request, uint64_t request_size,
                          uint8_t** reply, uint64_t* reply_size,
                          char* error, size_t error_size);

int csap_adi_state(csap_modern_adi_t* adi,
                   uint8_t** state, uint64_t* state_size,
                   char* error, size_t error_size);

void csap_adi_free(void* buffer);

void csap_adi_close(csap_modern_adi_t* adi);

#ifdef __cplusplus
}
#endif

#endif // CSAP_STORE_RUNTIME_H
