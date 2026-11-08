#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <CommonCrypto/CommonDigest.h>

#include "guest.h"
#include "shims.h"
#include "store_runtime.h"

// 与 Go 侧 internal/sap/machine 的常量保持一致。
#define ADI_COREFP_BASE                 0x0000100000000000ULL

#define ADI_STORE_AGENT_BASE            0x00001000c0000000ULL
#define ADI_STORE_AGENT_GLOBAL_INIT     (ADI_STORE_AGENT_BASE + 0x1312fcULL)
#define ADI_STORE_AGENT_GLOBAL_CLOSE    (ADI_STORE_AGENT_BASE + 0x130eb4ULL)
#define ADI_STORE_AGENT_SCINFO_PATH     "/Users/Shared/SC Info"

#define ADI_START_ENTRY                 (ADI_STORE_AGENT_BASE + 0x1b4400ULL)
#define ADI_END_ENTRY                   (ADI_STORE_AGENT_BASE + 0x1d5124ULL)
#define ADI_OTP_ENTRY                   (ADI_STORE_AGENT_BASE + 0x1dab04ULL)
#define ADI_KEYBAG_ENTRY                (ADI_STORE_AGENT_BASE + 0x16e0f8ULL)
#define ADI_STATE_PATH                  "/var/db/fpsd/adi/adi.pb"

#define ADI_DAEMON_BASE                 0x0000200000000000ULL
#define ADI_DAEMON_ENTRY                (ADI_DAEMON_BASE + 0x11180ULL)

#define ADI_FAIRPLAY_BASE               0x0000600000000000ULL
#define ADI_FAIRPLAY_ENTRY              (ADI_FAIRPLAY_BASE + 0x332040ULL)

// 保留 prelinked 镜像原始 0x510 页偏置，使 ADRP 引用与数据段保持同一 slide。
#define ADI_KEXT_BASE                   0x0000700000000510ULL
#define ADI_KEXT_START                  (ADI_KEXT_BASE + 0x2bca984ULL)
#define ADI_KEXT_SETUP                  (ADI_KEXT_BASE + 0x2c67e50ULL)
#define ADI_KEXT_INIT                   (ADI_KEXT_BASE + 0x2bca714ULL)
#define ADI_KEXT_ENTRY                  (ADI_KEXT_BASE + 0x2cf978cULL)
#define ADI_KEXT_KERNEL_BASE            0xfffffe0007004000ULL
#define ADI_KEXT_STACK_PROBE            (ADI_KEXT_BASE + 0xb8c028ULL)
#define ADI_KEXT_STACK_PROBE_EXPECTED   (ADI_KEXT_BASE + 0x2c66248ULL)

#define ADI_FAKE_HANDLE                 UINT64_MAX
#define ADI_MAX_OUTPUT                  (1ULL << 20)
#define ADI_MAX_XPC_REQUEST             (1ULL << 20)

// ==================== 固定资产表 ====================

typedef struct {
    const char* name;
    uint64_t    size;
    const char* digest;
} adi_asset_spec_t;

static const adi_asset_spec_t adi_asset_specs[] = {
    {
        "AppleMediaServices", 14813888,
        "95f4558aa2c0ccd9f96ed479e336b630b46bf4b4e0baabc1c1ac8c7d55e21ab4",
    },
    {
        "commerce", 8092640,
        "76de40a4a32f691947cb926ce3b128d2fc446f7cac9755f831c406cf5a316ac9",
    },
    {
        "adid", 9797952,
        "1fec225b6917206e3d9b00fe636c04878f82bfd06a87a4b6941711de60efab5b",
    },
    {
        "CoreFP", 94842464,
        "2c30fa2b5f695fd66c0360dce72f54757d03ddb7107549715c12cb359a003b46",
    },
    {
        "CoreFP.icxs", 7365344,
        "cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b",
    },
    {
        "fairplayd", 37689264,
        "28b4c7b2a5a0409c5020da55fc3984713a8e2b0eec8557076c8717f7166d003e",
    },
    {
        "FairPlayIOKit", 2132320,
        "47452960ec010d3a80b02cceec73a65f8a9758850fd0fb7b2fdac7a5d1b81025",
    },
};

#define ADI_ASSET_COUNT (sizeof(adi_asset_specs) / sizeof(adi_asset_specs[0]))

// ==================== shared cache 元数据 ====================

static const csap_guest_symbol_t adi_shared_cache_functions[] = {
    {0x0000000180675ce8ULL, "_malloc"},
    {0x00000001806766f0ULL, "_free"},
    {0x00000001806cf570ULL, "_dispatch_once"},
    {0x000000018071acc8ULL, "_sysctlbyname"},
    {0x000000018071bec4ULL, "_gettimeofday"},
    {0x0000000180721fb8ULL, "_arc4random"},
    {0x00000001807238a4ULL, "___memset_chk"},
    {0x00000001807903c4ULL, "_abort"},
    {0x0000000180849604ULL, "___error"},
    {0x0000000180889bc4ULL, "_pthread_once"},
    {0x000000018088a6f8ULL, "_pthread_rwlock_unlock"},
    {0x000000018088a7c0ULL, "_pthread_rwlock_wrlock"},
    {0x000000018088b2d8ULL, "_pthread_rwlock_init"},
    {0x0000000180894b40ULL, "_strlen"},
    {0x00000001808cf540ULL, "_CFStringCreateWithCString"},
    {0x00000001808d4200ULL, "_CFStringGetLength"},
    {0x00000001808d44dcULL, "_CFStringGetCString"},
    {0x00000001808d7278ULL, "_CFRelease"},
    {0x00000001808e89e8ULL, "_CFDataGetLength"},
    {0x0000000184d6b4ccULL, "_IOServiceMatching"},
    {0x0000000184d6c168ULL, "_IOServiceGetMatchingServices"},
    {0x0000000184d6c4fcULL, "_IOIteratorNext"},
    {0x0000000184d6cb50ULL, "_IOObjectRelease"},
};

static const csap_guest_symbol_t adi_shared_cache_slots[] = {
    {0x00000001e02205c0ULL, "___stack_chk_guard"},
    {0x00000001e800c958ULL, "___chkstk_darwin"},
};

static const char* const adi_core_export_names[] = {
    "_WIn9UJ86JKdV4dM",
    "_X46O5IeS",
    "_YlCJ3lg",
    "_dku592fbFAj",
    "_fdjkDSAFjklaf2s",
    "_lxpgvVMLd0S7uRl",
};

static const char* const adi_entry_names[] = {
    "_cp2g1b9ro",
    "_Mib5yocT",
    "_Fc3vhtJDvr",
    "_IPaI1oem5iL",
    "_jEHf8Xzsv8K",
};

static const char* const adi_zero_return_aliases[] = {
    "_pthread_rwlock_rdlock",
    "_pthread_rwlock_rdlock$UNIX2003",
    "_pthread_mutex_init",
    "_pthread_mutex_destroy",
    "_pthread_rwlock_destroy",
};

typedef struct {
    bool pause_run_loop;
    bool zero_return_aliases;
} adi_shim_config_t;

// ==================== 结构体 ====================

struct csap_modern_adi {
    csap_guest_t* runtime;
    csap_guest_t* daemon;
    csap_guest_t* fairplay;
    csap_guest_t* kernel;

    uint64_t kernel_context;
    uint32_t store_global;
    uint64_t daemon_handler;

    // FairPlay handler 返回给 shim 平台的输出，至少保持到下一次调用。
    uint8_t* fairplay_output;
    uint64_t fairplay_output_size;
    uint8_t* fairplay_indirect;
    uint64_t fairplay_indirect_size;
    uint8_t* mach_reply;
    uint64_t mach_reply_size;

    char last_error[256];
};

// ==================== 错误处理 ====================

static void adi_set_error(char* error, size_t error_size, const char* format, ...) {
    if (error == NULL || error_size == 0) return;

    va_list args;
    va_start(args, format);
    vsnprintf(error, error_size, format, args);
    va_end(args);
}

static int adi_fail(csap_modern_adi_t* adi, const char* format, ...) {
    if (adi == NULL) return -1;

    va_list args;
    va_start(args, format);
    vsnprintf(adi->last_error, sizeof(adi->last_error), format, args);
    va_end(args);

    return -1;
}

static int adi_report(csap_modern_adi_t* adi, char* error, size_t error_size, const char* fallback) {
    if (adi != NULL && adi->last_error[0] != '\0') {
        adi_set_error(error, error_size, "%s", adi->last_error);
    } else {
        adi_set_error(error, error_size, "%s", fallback);
    }
    return -1;
}

// ==================== 资产加载 ====================

static int adi_parse_digest(const char* hex, uint8_t digest[32]) {
    if (hex == NULL || strlen(hex) != 64) return -1;

    for (int i = 0; i < 32; i++) {
        unsigned int byte = 0;
        if (sscanf(hex + i * 2, "%2x", &byte) != 1) return -1;
        digest[i] = (uint8_t)byte;
    }
    return 0;
}

static uint8_t* adi_read_asset(const char* path, uint64_t expected_size,
                               const uint8_t expected_digest[32],
                               char* error, size_t error_size) {
    FILE* file = fopen(path, "rb");
    if (file == NULL) {
        adi_set_error(error, error_size, "open cached Apple asset %s: %s", path, strerror(errno));
        return NULL;
    }

    if (fseek(file, 0, SEEK_END) != 0) {
        adi_set_error(error, error_size, "size cached Apple asset %s: %s", path, strerror(errno));
        fclose(file);
        return NULL;
    }

    long length = ftell(file);
    if (length < 0 || (uint64_t)length != expected_size) {
        adi_set_error(error, error_size, "cached Apple asset %s has unexpected size %ld", path, length);
        fclose(file);
        return NULL;
    }

    if (fseek(file, 0, SEEK_SET) != 0) {
        adi_set_error(error, error_size, "read cached Apple asset %s: %s", path, strerror(errno));
        fclose(file);
        return NULL;
    }

    uint8_t* data = malloc(expected_size > 0 ? (size_t)expected_size : 1);
    if (data == NULL) {
        adi_set_error(error, error_size, "allocate cached Apple asset %s", path);
        fclose(file);
        return NULL;
    }

    if (expected_size > 0 && fread(data, 1, (size_t)expected_size, file) != (size_t)expected_size) {
        adi_set_error(error, error_size, "read cached Apple asset %s: %s", path, strerror(errno));
        free(data);
        fclose(file);
        return NULL;
    }

    fclose(file);

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data, (CC_LONG)expected_size, digest);
    if (memcmp(digest, expected_digest, sizeof(digest)) != 0) {
        adi_set_error(error, error_size, "cached Apple asset %s digest does not match", path);
        free(data);
        return NULL;
    }

    return data;
}

int csap_store_assets_load(const char* directory, csap_store_assets_t* assets,
                           char* error, size_t error_size) {
    if (directory == NULL || assets == NULL) {
        adi_set_error(error, error_size, "store asset directory is unavailable");
        return -1;
    }

    memset(assets, 0, sizeof(*assets));
    uint8_t* files[ADI_ASSET_COUNT];
    memset(files, 0, sizeof(files));

    for (size_t i = 0; i < ADI_ASSET_COUNT; i++) {
        char path[1024];
        int written = snprintf(path, sizeof(path), "%s/%s", directory, adi_asset_specs[i].name);
        if (written < 0 || (size_t)written >= sizeof(path)) {
            adi_set_error(error, error_size, "cached Apple asset path is too long");
            goto fail;
        }

        uint8_t digest[32];
        if (adi_parse_digest(adi_asset_specs[i].digest, digest) != 0) {
            adi_set_error(error, error_size, "cached Apple asset digest is invalid");
            goto fail;
        }

        files[i] = adi_read_asset(path, adi_asset_specs[i].size, digest, error, error_size);
        if (files[i] == NULL) goto fail;
    }

    assets->apple_media_services = files[0];
    assets->apple_media_services_size = adi_asset_specs[0].size;
    assets->commerce = files[1];
    assets->commerce_size = adi_asset_specs[1].size;
    assets->adid = files[2];
    assets->adid_size = adi_asset_specs[2].size;
    assets->corefp = files[3];
    assets->corefp_size = adi_asset_specs[3].size;
    assets->corefp_icxs = files[4];
    assets->corefp_icxs_size = adi_asset_specs[4].size;
    assets->fairplayd = files[5];
    assets->fairplayd_size = adi_asset_specs[5].size;
    assets->fairplay_kext = files[6];
    assets->fairplay_kext_size = adi_asset_specs[6].size;

    return 0;

fail:
    for (size_t i = 0; i < ADI_ASSET_COUNT; i++) {
        free(files[i]);
    }
    memset(assets, 0, sizeof(*assets));
    return -1;
}

void csap_store_assets_free(csap_store_assets_t* assets) {
    if (assets == NULL) return;

    free((void*)assets->corefp);
    free((void*)assets->corefp_icxs);
    free((void*)assets->apple_media_services);
    free((void*)assets->commerce);
    free((void*)assets->adid);
    free((void*)assets->fairplayd);
    free((void*)assets->fairplay_kext);

    memset(assets, 0, sizeof(*assets));
}

// ==================== 运行时装载 ====================

static void adi_configure_shims(csap_shims_t* shims, void* context) {
    adi_shim_config_t* config = context;
    if (config == NULL) return;

    if (config->pause_run_loop) {
        csap_shims_set_pause_run_loop(shims, true);
    }
    if (config->zero_return_aliases) {
        csap_shims_add_zero_return_aliases(shims, adi_zero_return_aliases,
                                           (uint32_t)(sizeof(adi_zero_return_aliases) /
                                                      sizeof(adi_zero_return_aliases[0])));
    }
}

static csap_guest_t* adi_open_guest(const csap_store_assets_t* assets,
                                    const char* extra_name,
                                    const uint8_t* extra_data, uint64_t extra_size,
                                    uint64_t extra_base, uint64_t kernel_base,
                                    bool pause_run_loop, bool zero_return_aliases,
                                    char* error, size_t error_size) {
    csap_guest_image_t images[3];
    memset(images, 0, sizeof(images));

    images[0].name = "CoreFP";
    images[0].data = assets->corefp;
    images[0].size = assets->corefp_size;
    images[0].base = ADI_COREFP_BASE;

    images[1].name = "AppleMediaServices";
    images[1].data = assets->apple_media_services;
    images[1].size = assets->apple_media_services_size;
    images[1].prelinked = true;
    images[1].prelinked_symbols = adi_shared_cache_functions;
    images[1].prelinked_symbol_count =
        (uint32_t)(sizeof(adi_shared_cache_functions) / sizeof(adi_shared_cache_functions[0]));
    images[1].slots = adi_shared_cache_slots;
    images[1].slot_count = (uint32_t)(sizeof(adi_shared_cache_slots) / sizeof(adi_shared_cache_slots[0]));
    images[1].functions = adi_shared_cache_functions;
    images[1].function_count = images[1].prelinked_symbol_count;

    uint32_t image_count = 2;
    if (extra_data != NULL && extra_size != 0) {
        images[2].name = extra_name;
        images[2].data = extra_data;
        images[2].size = extra_size;
        images[2].base = extra_base;
        images[2].kernel_base = kernel_base;
        image_count = 3;
    }

    adi_shim_config_t config;
    config.pause_run_loop = pause_run_loop;
    config.zero_return_aliases = zero_return_aliases;

    csap_guest_options_t options;
    memset(&options, 0, sizeof(options));
    options.corefp_icxs = assets->corefp_icxs;
    options.corefp_icxs_size = assets->corefp_icxs_size;
    options.core_export_names = adi_core_export_names;
    options.core_export_count =
        (uint32_t)(sizeof(adi_core_export_names) / sizeof(adi_core_export_names[0]));
    options.entry_names = adi_entry_names;
    options.entry_count = (uint32_t)(sizeof(adi_entry_names) / sizeof(adi_entry_names[0]));
    options.configure_shims = adi_configure_shims;
    options.configure_context = &config;

    csap_guest_t* guest = csap_guest_open(images, image_count, &options);
    if (guest == NULL) {
        adi_set_error(error, error_size, "open %s runtime", extra_name != NULL ? extra_name : "store");
    }

    return guest;
}

// ==================== 内存辅助 ====================

static int adi_read_u64(csap_guest_t* guest, uint64_t address, uint64_t* value) {
    return csap_guest_read(guest, address, value, sizeof(*value));
}

static int adi_read_u32(csap_guest_t* guest, uint64_t address, uint32_t* value) {
    return csap_guest_read(guest, address, value, sizeof(*value));
}

// ==================== 内核上下文 ====================

static int adi_initialize_fairplay_kernel(csap_modern_adi_t* adi, char* error, size_t error_size) {
    csap_guest_begin_call(adi->kernel);

    uint64_t status = 0;
    if (csap_guest_invoke(adi->kernel, ADI_KEXT_START, NULL, 0, NULL) != 0) {
        csap_guest_clear_scratch(adi->kernel);
        adi_fail(adi, "start modern FairPlay kernel");
        return adi_report(adi, error, error_size, "start modern FairPlay kernel");
    }

    if (csap_guest_invoke(adi->kernel, ADI_KEXT_SETUP, NULL, 0, &status) != 0) {
        csap_guest_clear_scratch(adi->kernel);
        adi_fail(adi, "set up modern FairPlay kernel");
        return adi_report(adi, error, error_size, "set up modern FairPlay kernel");
    }

    if ((int32_t)status != 0) {
        csap_guest_clear_scratch(adi->kernel);
        adi_fail(adi, "set up modern FairPlay kernel: status %d", (int32_t)status);
        return adi_report(adi, error, error_size, "set up modern FairPlay kernel");
    }

    uint64_t output = csap_guest_scratch(adi->kernel, NULL, 0, 8);
    if (output == 0) {
        csap_guest_clear_scratch(adi->kernel);
        adi_fail(adi, "allocate modern FairPlay kernel output");
        return adi_report(adi, error, error_size, "allocate modern FairPlay kernel output");
    }

    uint64_t task = csap_shims_allocate(csap_guest_shims(adi->kernel), 0x1000);
    if (task == 0) {
        csap_guest_clear_scratch(adi->kernel);
        adi_fail(adi, "allocate modern FairPlay kernel task");
        return adi_report(adi, error, error_size, "allocate modern FairPlay kernel task");
    }

    static const uint8_t zeros[0x1000];
    if (csap_guest_write(adi->kernel, task, zeros, sizeof(zeros)) != 0) {
        csap_guest_clear_scratch(adi->kernel);
        adi_fail(adi, "initialize modern FairPlay kernel task");
        return adi_report(adi, error, error_size, "initialize modern FairPlay kernel task");
    }

    uint64_t arguments[4] = {0, output, 0, task};
    if (csap_guest_invoke(adi->kernel, ADI_KEXT_INIT, arguments, 4, &status) != 0) {
        csap_guest_clear_scratch(adi->kernel);
        adi_fail(adi, "initialize modern FairPlay kernel session");
        return adi_report(adi, error, error_size, "initialize modern FairPlay kernel session");
    }

    if ((int32_t)status != 0) {
        csap_guest_clear_scratch(adi->kernel);
        adi_fail(adi, "initialize modern FairPlay kernel session: status %d", (int32_t)status);
        return adi_report(adi, error, error_size, "initialize modern FairPlay kernel session");
    }

    uint64_t context = 0;
    if (adi_read_u64(adi->kernel, output, &context) != 0) {
        csap_guest_clear_scratch(adi->kernel);
        adi_fail(adi, "read modern FairPlay kernel session context");
        return adi_report(adi, error, error_size, "read modern FairPlay kernel session context");
    }

    if (context == 0) {
        csap_guest_clear_scratch(adi->kernel);
        adi_fail(adi, "modern FairPlay kernel returned no session context");
        return adi_report(adi, error, error_size, "modern FairPlay kernel returned no session context");
    }

    csap_guest_clear_scratch(adi->kernel);

    adi->kernel_context = context;

    return 0;
}

// ==================== FairPlay 回调 ====================

static int adi_prepare_fairplay_outputs(csap_modern_adi_t* adi,
                                        const uint8_t* input, uint64_t input_size,
                                        int output_capacity,
                                        const uint8_t* updated, uint64_t updated_size,
                                        int32_t code,
                                        csap_shims_fairplay_call_t* call) {
    uint64_t output_size = input_size;
    uint64_t capacity = output_capacity > 0 ? (uint64_t)output_capacity : 0;
    if (output_size > capacity) {
        output_size = capacity;
    }

    adi->fairplay_output_size = 0;
    if (output_size > 0 && input != NULL) {
        uint8_t* buffer = realloc(adi->fairplay_output, (size_t)output_size);
        if (buffer == NULL) return -1;
        adi->fairplay_output = buffer;
        memcpy(buffer, input, (size_t)output_size);
        adi->fairplay_output_size = output_size;
    }

    adi->fairplay_indirect_size = 0;
    if (updated_size > 0 && updated != NULL) {
        uint8_t* buffer = realloc(adi->fairplay_indirect, (size_t)updated_size);
        if (buffer == NULL) return -1;
        adi->fairplay_indirect = buffer;
        memcpy(buffer, updated, (size_t)updated_size);
        adi->fairplay_indirect_size = updated_size;
    }

    call->output = adi->fairplay_output;
    call->output_size = adi->fairplay_output_size;
    call->indirect_output = adi->fairplay_indirect;
    call->indirect_output_size = adi->fairplay_indirect_size;
    call->code = code;

    return 0;
}

static int adi_handle_fairplay_message(void* context, csap_shims_fairplay_call_t* call) {
    csap_modern_adi_t* adi = context;
    if (adi == NULL || call == NULL) return -1;

    if (adi->kernel != NULL) {
        uint64_t probe = 0;
        if (adi_read_u64(adi->kernel, ADI_KEXT_STACK_PROBE, &probe) != 0 ||
            probe != ADI_KEXT_STACK_PROBE_EXPECTED) {
            fprintf(stderr, "csap modern ADI: FairPlay kernel stack probe is %#llx\n",
                    (unsigned long long)probe);
            return -1;
        }

        csap_guest_begin_call(adi->kernel);

        uint64_t message = csap_guest_scratch(adi->kernel, call->indirect,
                                              call->indirect_size, call->indirect_size);
        if (message == 0) {
            csap_guest_clear_scratch(adi->kernel);
            fprintf(stderr, "csap modern ADI: FairPlay kernel scratch is unavailable\n");
            return -1;
        }

        uint64_t arguments[3] = {message, call->indirect_size, adi->kernel_context};
        uint64_t status = 0;
        if (csap_guest_invoke(adi->kernel, ADI_KEXT_ENTRY, arguments, 3, &status) != 0) {
            csap_guest_clear_scratch(adi->kernel);
            fprintf(stderr, "csap modern ADI: run modern FairPlay kernel message\n");
            return -1;
        }

        uint8_t* updated = NULL;
        if (call->indirect_size > 0) {
            updated = malloc((size_t)call->indirect_size);
            if (updated != NULL &&
                csap_guest_read(adi->kernel, message, updated, call->indirect_size) != 0) {
                free(updated);
                updated = NULL;
            }
        }

        csap_guest_clear_scratch(adi->kernel);

        int result = adi_prepare_fairplay_outputs(adi, call->input, call->input_size,
                                                  call->output_capacity,
                                                  updated, call->indirect_size,
                                                  (int32_t)status, call);
        free(updated);

        return result;
    }

    csap_shims_t* shims = csap_guest_shims(adi->fairplay);
    uint64_t callback = csap_shims_mach_port_callback(shims);
    uint64_t info = csap_shims_mach_port_info(shims);
    if (callback == 0) {
        fprintf(stderr, "csap modern ADI: FairPlay daemon installed no message callback\n");
        return -1;
    }

    csap_guest_begin_call(adi->fairplay);

    uint64_t message = csap_guest_scratch(adi->fairplay, call->indirect,
                                          call->indirect_size, call->indirect_size);
    if (message == 0) {
        csap_guest_clear_scratch(adi->fairplay);
        fprintf(stderr, "csap modern ADI: FairPlay daemon scratch is unavailable\n");
        return -1;
    }

    uint64_t arguments[4] = {ADI_FAKE_HANDLE, message, call->indirect_size, info};
    if (csap_guest_invoke(adi->fairplay, callback, arguments, 4, NULL) != 0) {
        csap_guest_clear_scratch(adi->fairplay);
        fprintf(stderr, "csap modern ADI: run modern FairPlay message callback\n");
        return -1;
    }

    uint8_t* updated = NULL;
    if (call->indirect_size > 0) {
        updated = malloc((size_t)call->indirect_size);
        if (updated != NULL &&
            csap_guest_read(adi->fairplay, message, updated, call->indirect_size) != 0) {
            free(updated);
            updated = NULL;
        }
    }

    csap_guest_clear_scratch(adi->fairplay);

    int result = adi_prepare_fairplay_outputs(adi, call->input, call->input_size,
                                              call->output_capacity,
                                              updated, call->indirect_size, 0, call);
    free(updated);

    return result;
}

static int adi_handle_fairplay_mach_rpc(void* context, csap_shims_mach_rpc_call_t* call) {
    csap_modern_adi_t* adi = context;
    if (adi == NULL || call == NULL || adi->fairplay == NULL) return -1;

    csap_shims_t* shims = csap_guest_shims(adi->fairplay);
    uint64_t callback = csap_shims_mach_port_callback(shims);
    uint64_t info = csap_shims_mach_port_info(shims);
    if (callback == 0) {
        fprintf(stderr, "csap modern ADI: FairPlay daemon installed no message callback\n");
        return -1;
    }

    uint64_t receive = call->receive_size > 0 ? (uint64_t)call->receive_size : 0;
    uint64_t reserve = call->request_size > receive ? call->request_size : receive;

    csap_guest_begin_call(adi->fairplay);

    uint64_t message = csap_guest_scratch(adi->fairplay, call->request, call->request_size, reserve);
    if (message == 0) {
        csap_guest_clear_scratch(adi->fairplay);
        fprintf(stderr, "csap modern ADI: FairPlay Mach scratch is unavailable\n");
        return -1;
    }

    csap_shims_clear_mach_message_reply(shims);

    uint64_t arguments[4] = {ADI_FAKE_HANDLE, message, call->request_size, info};
    if (csap_guest_invoke(adi->fairplay, callback, arguments, 4, NULL) != 0) {
        csap_guest_clear_scratch(adi->fairplay);
        fprintf(stderr, "csap modern ADI: run modern FairPlay Mach callback\n");
        return -1;
    }

    uint64_t reply_size = 0;
    const uint8_t* reply = csap_shims_mach_message_reply(shims, &reply_size);
    if (reply == NULL || reply_size == 0) {
        csap_guest_clear_scratch(adi->fairplay);
        fprintf(stderr, "csap modern ADI: FairPlay daemon returned no Mach reply\n");
        return -1;
    }

    uint8_t* buffer = realloc(adi->mach_reply, (size_t)reply_size);
    if (buffer == NULL) {
        csap_guest_clear_scratch(adi->fairplay);
        return -1;
    }

    adi->mach_reply = buffer;
    memcpy(buffer, reply, (size_t)reply_size);
    adi->mach_reply_size = reply_size;

    csap_guest_clear_scratch(adi->fairplay);

    call->reply = buffer;
    call->reply_size = reply_size;

    return 0;
}

// ==================== 守护进程 ====================

static int adi_invoke_daemon_block(csap_modern_adi_t* adi, uint64_t block, uint64_t argument,
                                   char* error, size_t error_size) {
    uint64_t handler = 0;
    if (adi_read_u64(adi->daemon, block + 16, &handler) != 0) {
        adi_fail(adi, "read modern ADI daemon block handler");
        return adi_report(adi, error, error_size, "read modern ADI daemon block handler");
    }

    if (handler == 0) {
        adi_fail(adi, "modern ADI daemon block handler is unavailable");
        return adi_report(adi, error, error_size, "modern ADI daemon block handler is unavailable");
    }

    uint64_t arguments[2] = {block, argument};
    if (csap_guest_invoke(adi->daemon, handler, arguments, 2, NULL) != 0) {
        adi_fail(adi, "run modern ADI daemon block");
        return adi_report(adi, error, error_size, "run modern ADI daemon block");
    }

    return 0;
}

static int adi_initialize_daemon(csap_modern_adi_t* adi, char* error, size_t error_size) {
    // 入口可能返回错误但仍安装事件处理器，与 Go 侧一致。
    uint64_t arguments[4] = {0, 0, 0, 0};
    csap_guest_invoke(adi->daemon, ADI_DAEMON_ENTRY, arguments, 4, NULL);

    csap_shims_t* shims = csap_guest_shims(adi->daemon);
    uint64_t listener = csap_shims_xpc_event_handler(shims);
    if (listener == 0) {
        adi_fail(adi, "initialize modern ADI daemon: no event handler");
        return adi_report(adi, error, error_size, "initialize modern ADI daemon");
    }

    uint64_t connection = csap_shims_new_xpc_object(shims, NULL, 0, false);
    if (connection == 0) {
        adi_fail(adi, "initialize modern ADI daemon: no connection object");
        return adi_report(adi, error, error_size, "initialize modern ADI daemon");
    }

    if (adi_invoke_daemon_block(adi, listener, connection, error, error_size) != 0) {
        return -1;
    }

    uint64_t handler = csap_shims_xpc_event_handler(shims);
    if (handler == listener) {
        adi_fail(adi, "modern ADI daemon did not install a request handler");
        return adi_report(adi, error, error_size, "modern ADI daemon did not install a request handler");
    }

    adi->daemon_handler = handler;

    return 0;
}

// ==================== XPC 往返 ====================

static int adi_invoke(csap_modern_adi_t* adi, uint64_t function,
                      const uint64_t* arguments, uint32_t argument_count,
                      uint64_t* result, char* error, size_t error_size) {
    csap_shims_t* runtime_shims = csap_guest_shims(adi->runtime);
    csap_shims_t* daemon_shims = csap_guest_shims(adi->daemon);

    csap_shims_clear_xpc_data(runtime_shims);
    csap_shims_set_xpc_sync_reply(runtime_shims, NULL, 0);

    csap_guest_invoke(adi->runtime, function, arguments, argument_count, NULL);

    uint64_t request_size = 0;
    const uint8_t* request = csap_shims_xpc_data(runtime_shims, &request_size);
    if (request == NULL || request_size == 0) {
        adi_fail(adi, "modern ADI client created no daemon request");
        return adi_report(adi, error, error_size, "modern ADI client created no daemon request");
    }

    csap_shims_clear_xpc_reply(daemon_shims);

    uint64_t request_object = csap_shims_new_xpc_object(daemon_shims, request, request_size, true);
    if (request_object == 0) {
        adi_fail(adi, "modern ADI daemon request object is unavailable");
        return adi_report(adi, error, error_size, "modern ADI daemon request object is unavailable");
    }

    if (adi_invoke_daemon_block(adi, adi->daemon_handler, request_object, error, error_size) != 0) {
        return -1;
    }

    uint64_t reply_size = 0;
    const uint8_t* reply = csap_shims_xpc_reply(daemon_shims, &reply_size);
    if (!csap_shims_xpc_replied(daemon_shims) || reply == NULL || reply_size == 0) {
        adi_fail(adi, "modern ADI daemon returned no reply");
        return adi_report(adi, error, error_size, "modern ADI daemon returned no reply");
    }

    csap_shims_set_xpc_sync_reply(runtime_shims, reply, reply_size);

    if (csap_guest_invoke(adi->runtime, function, arguments, argument_count, result) != 0) {
        adi_fail(adi, "run modern ADI client request");
        return adi_report(adi, error, error_size, "run modern ADI client request");
    }

    return 0;
}

// ==================== 输出 ====================

static int adi_read_output(csap_modern_adi_t* adi, uint64_t pointer_field, uint64_t length_field,
                           uint8_t** output, uint64_t* output_size,
                           char* error, size_t error_size) {
    uint64_t pointer = 0;
    uint32_t length = 0;
    if (adi_read_u64(adi->runtime, pointer_field, &pointer) != 0 ||
        adi_read_u32(adi->runtime, length_field, &length) != 0) {
        adi_fail(adi, "read modern ADI output fields");
        return adi_report(adi, error, error_size, "read modern ADI output fields");
    }

    if (pointer == 0 || length == 0 || length > ADI_MAX_OUTPUT) {
        adi_fail(adi, "modern ADI returned invalid output");
        return adi_report(adi, error, error_size, "modern ADI returned invalid output");
    }

    uint8_t* buffer = malloc(length);
    if (buffer == NULL) {
        adi_fail(adi, "allocate modern ADI output");
        return adi_report(adi, error, error_size, "allocate modern ADI output");
    }

    if (csap_guest_read(adi->runtime, pointer, buffer, length) != 0) {
        free(buffer);
        adi_fail(adi, "read modern ADI output");
        return adi_report(adi, error, error_size, "read modern ADI output");
    }

    *output = buffer;
    *output_size = length;

    return 0;
}

// ==================== 公开 API ====================

static bool adi_assets_are_complete(const csap_store_assets_t* assets) {
    return assets->corefp != NULL && assets->corefp_size != 0 &&
           assets->corefp_icxs != NULL && assets->corefp_icxs_size != 0 &&
           assets->apple_media_services != NULL && assets->apple_media_services_size != 0 &&
           assets->commerce != NULL && assets->commerce_size != 0 &&
           assets->adid != NULL && assets->adid_size != 0 &&
           assets->fairplayd != NULL && assets->fairplayd_size != 0;
}

csap_modern_adi_t* csap_adi_open(const csap_store_assets_t* assets,
                                 const uint8_t host_uuid[16],
                                 const uint8_t* state, uint64_t state_size,
                                 char* error, size_t error_size) {
    if (error != NULL && error_size > 0) error[0] = '\0';

    if (assets == NULL || host_uuid == NULL) {
        adi_set_error(error, error_size, "modern ADI assets are unavailable");
        return NULL;
    }

    if (!adi_assets_are_complete(assets)) {
        adi_set_error(error, error_size, "modern ADI assets are incomplete");
        return NULL;
    }

    csap_modern_adi_t* adi = calloc(1, sizeof(*adi));
    if (adi == NULL) {
        adi_set_error(error, error_size, "allocate modern ADI runtime");
        return NULL;
    }

    adi->runtime = adi_open_guest(assets, "commerce", assets->commerce, assets->commerce_size,
                                  ADI_STORE_AGENT_BASE, 0, false, true, error, error_size);
    if (adi->runtime == NULL) goto fail;

    adi->daemon = adi_open_guest(assets, "adid", assets->adid, assets->adid_size,
                                 ADI_DAEMON_BASE, 0, true, false, error, error_size);
    if (adi->daemon == NULL) goto fail;

    adi->fairplay = adi_open_guest(assets, "fairplayd", assets->fairplayd, assets->fairplayd_size,
                                   ADI_FAIRPLAY_BASE, 0, true, false, error, error_size);
    if (adi->fairplay == NULL) goto fail;

    csap_shims_set_host_uuid(csap_guest_shims(adi->runtime), host_uuid);
    csap_shims_set_host_uuid(csap_guest_shims(adi->daemon), host_uuid);
    csap_shims_set_host_uuid(csap_guest_shims(adi->fairplay), host_uuid);

    if (state != NULL && state_size != 0) {
        if (csap_shims_set_adi_file(csap_guest_shims(adi->daemon), ADI_STATE_PATH,
                                    state, state_size) != 0) {
            adi_set_error(error, error_size, "install modern ADI state");
            goto fail;
        }
    }

    if (assets->fairplay_kext != NULL && assets->fairplay_kext_size != 0) {
        adi->kernel = adi_open_guest(assets, "FairPlayIOKit",
                                     assets->fairplay_kext, assets->fairplay_kext_size,
                                     ADI_KEXT_BASE, ADI_KEXT_KERNEL_BASE,
                                     false, false, error, error_size);
        if (adi->kernel == NULL) goto fail;

        csap_shims_set_host_uuid(csap_guest_shims(adi->kernel), host_uuid);
        csap_shims_set_mach_rpc_handler(csap_guest_shims(adi->kernel),
                                        adi_handle_fairplay_mach_rpc, adi);

        if (adi_initialize_fairplay_kernel(adi, error, error_size) != 0) goto fail;
    }

    csap_shims_set_fairplay_handler(csap_guest_shims(adi->fairplay),
                                    adi_handle_fairplay_message, adi);

    uint64_t arguments[3] = {0, 0, 0};
    if (csap_guest_invoke(adi->fairplay, ADI_FAIRPLAY_ENTRY, arguments, 3, NULL) != 0) {
        adi_fail(adi, "initialize modern FairPlay daemon");
        adi_report(adi, error, error_size, "initialize modern FairPlay daemon");
        goto fail;
    }

    csap_shims_set_fairplay_handler(csap_guest_shims(adi->daemon),
                                    adi_handle_fairplay_message, adi);
    csap_shims_set_fairplay_handler(csap_guest_shims(adi->runtime),
                                    adi_handle_fairplay_message, adi);

    if (adi_initialize_daemon(adi, error, error_size) != 0) goto fail;

    return adi;

fail:
    csap_adi_close(adi);
    return NULL;
}

int csap_adi_start_provisioning(csap_modern_adi_t* adi, uint64_t dsid,
                                const uint8_t* spim, uint64_t spim_size,
                                uint8_t** output, uint64_t* output_size,
                                uint32_t* session,
                                char* error, size_t error_size) {
    if (output != NULL) *output = NULL;
    if (output_size != NULL) *output_size = 0;
    if (session != NULL) *session = 0;

    if (adi == NULL || adi->runtime == NULL) {
        adi_set_error(error, error_size, "modern ADI runtime is unavailable");
        return -1;
    }

    if (spim == NULL || spim_size == 0) {
        adi_set_error(error, error_size, "modern ADI spim is unavailable");
        return -1;
    }

    csap_guest_begin_call(adi->runtime);

    uint64_t input = csap_guest_scratch(adi->runtime, spim, spim_size, spim_size);
    uint64_t pointer_field = csap_guest_scratch(adi->runtime, NULL, 0, 8);
    uint64_t length_field = csap_guest_scratch(adi->runtime, NULL, 0, 4);
    uint64_t session_field = csap_guest_scratch(adi->runtime, NULL, 0, 4);

    if (input == 0 || pointer_field == 0 || length_field == 0 || session_field == 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "allocate modern ADI provisioning inputs");
        return adi_report(adi, error, error_size, "allocate modern ADI provisioning inputs");
    }

    uint64_t arguments[6] = {dsid, input, spim_size, pointer_field, length_field, session_field};
    uint64_t status = 0;
    if (adi_invoke(adi, ADI_START_ENTRY, arguments, 6, &status, error, error_size) != 0) {
        csap_guest_clear_scratch(adi->runtime);
        return -1;
    }

    if ((int32_t)status != 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "start modern ADI provisioning: status %d", (int32_t)status);
        return adi_report(adi, error, error_size, "start modern ADI provisioning");
    }

    uint8_t* result = NULL;
    uint64_t result_size = 0;
    if (adi_read_output(adi, pointer_field, length_field, &result, &result_size,
                        error, error_size) != 0) {
        csap_guest_clear_scratch(adi->runtime);
        return -1;
    }

    uint32_t session_value = 0;
    if (adi_read_u32(adi->runtime, session_field, &session_value) != 0) {
        free(result);
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "read modern ADI provisioning session");
        return adi_report(adi, error, error_size, "read modern ADI provisioning session");
    }

    csap_guest_clear_scratch(adi->runtime);

    if (output != NULL) {
        *output = result;
    } else {
        free(result);
    }
    if (output_size != NULL) *output_size = result_size;
    if (session != NULL) *session = session_value;

    return 0;
}

int csap_adi_end_provisioning(csap_modern_adi_t* adi, uint32_t session,
                              const uint8_t* setting_info, uint64_t setting_info_size,
                              const uint8_t* transport_key, uint64_t transport_key_size,
                              char* error, size_t error_size) {
    if (adi == NULL || adi->runtime == NULL) {
        adi_set_error(error, error_size, "modern ADI runtime is unavailable");
        return -1;
    }

    csap_guest_begin_call(adi->runtime);

    uint64_t setting_address = csap_guest_scratch(adi->runtime, setting_info,
                                                  setting_info_size, setting_info_size);
    uint64_t key_address = csap_guest_scratch(adi->runtime, transport_key,
                                              transport_key_size, transport_key_size);

    if (setting_address == 0 || key_address == 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "allocate modern ADI provisioning setting info");
        return adi_report(adi, error, error_size, "allocate modern ADI provisioning setting info");
    }

    uint64_t arguments[5] = {session, setting_address, setting_info_size,
                             key_address, transport_key_size};
    uint64_t status = 0;
    if (adi_invoke(adi, ADI_END_ENTRY, arguments, 5, &status, error, error_size) != 0) {
        csap_guest_clear_scratch(adi->runtime);
        return -1;
    }

    csap_guest_clear_scratch(adi->runtime);

    if ((int32_t)status != 0) {
        adi_fail(adi, "finish modern ADI provisioning: status %d", (int32_t)status);
        return adi_report(adi, error, error_size, "finish modern ADI provisioning");
    }

    return 0;
}

int csap_adi_request_otp(csap_modern_adi_t* adi, uint64_t dsid,
                         uint8_t** mid, uint64_t* mid_size,
                         uint8_t** otp, uint64_t* otp_size,
                         char* error, size_t error_size) {
    if (mid != NULL) *mid = NULL;
    if (mid_size != NULL) *mid_size = 0;
    if (otp != NULL) *otp = NULL;
    if (otp_size != NULL) *otp_size = 0;

    if (adi == NULL || adi->runtime == NULL) {
        adi_set_error(error, error_size, "modern ADI runtime is unavailable");
        return -1;
    }

    csap_guest_begin_call(adi->runtime);

    uint64_t mid_pointer = csap_guest_scratch(adi->runtime, NULL, 0, 8);
    uint64_t mid_length = csap_guest_scratch(adi->runtime, NULL, 0, 4);
    uint64_t otp_pointer = csap_guest_scratch(adi->runtime, NULL, 0, 8);
    uint64_t otp_length = csap_guest_scratch(adi->runtime, NULL, 0, 4);

    if (mid_pointer == 0 || mid_length == 0 || otp_pointer == 0 || otp_length == 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "allocate modern ADI OTP fields");
        return adi_report(adi, error, error_size, "allocate modern ADI OTP fields");
    }

    uint64_t arguments[5] = {dsid, mid_pointer, mid_length, otp_pointer, otp_length};
    uint64_t status = 0;
    if (adi_invoke(adi, ADI_OTP_ENTRY, arguments, 5, &status, error, error_size) != 0) {
        csap_guest_clear_scratch(adi->runtime);
        return -1;
    }

    if ((int32_t)status != 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "request modern ADI OTP: status %d", (int32_t)status);
        return adi_report(adi, error, error_size, "request modern ADI OTP");
    }

    uint8_t* mid_value = NULL;
    uint64_t mid_value_size = 0;
    uint8_t* otp_value = NULL;
    uint64_t otp_value_size = 0;

    if (adi_read_output(adi, mid_pointer, mid_length, &mid_value, &mid_value_size,
                        error, error_size) != 0) {
        csap_guest_clear_scratch(adi->runtime);
        return -1;
    }

    if (adi_read_output(adi, otp_pointer, otp_length, &otp_value, &otp_value_size,
                        error, error_size) != 0) {
        free(mid_value);
        csap_guest_clear_scratch(adi->runtime);
        return -1;
    }

    csap_guest_clear_scratch(adi->runtime);

    if (mid != NULL) {
        *mid = mid_value;
    } else {
        free(mid_value);
    }
    if (mid_size != NULL) *mid_size = mid_value_size;
    if (otp != NULL) {
        *otp = otp_value;
    } else {
        free(otp_value);
    }
    if (otp_size != NULL) *otp_size = otp_value_size;

    return 0;
}

static int adi_hardware_block(const uint8_t* hardware_id, uint64_t hardware_id_size,
                              uint8_t output[24], char* error, size_t error_size) {
    if (hardware_id == NULL || hardware_id_size == 0 || hardware_id_size > 20) {
        adi_set_error(error, error_size, "hardware ID must contain between 1 and 20 bytes");
        return -1;
    }

    memset(output, 0, 24);
    uint32_t length = (uint32_t)hardware_id_size;
    output[0] = (uint8_t)(length & 0xff);
    output[1] = (uint8_t)((length >> 8) & 0xff);
    output[2] = (uint8_t)((length >> 16) & 0xff);
    output[3] = (uint8_t)((length >> 24) & 0xff);
    memcpy(output + 4, hardware_id, (size_t)hardware_id_size);

    return 0;
}

int csap_adi_import_keybag(csap_modern_adi_t* adi,
                           const uint8_t* hardware_id, uint64_t hardware_id_size,
                           const uint8_t* keybag, uint64_t keybag_size,
                           char* error, size_t error_size) {
    if (adi == NULL || adi->runtime == NULL) {
        adi_set_error(error, error_size, "modern ADI runtime is unavailable");
        return -1;
    }

    uint8_t hardware[24];
    if (adi_hardware_block(hardware_id, hardware_id_size, hardware, error, error_size) != 0) {
        return -1;
    }

    csap_guest_begin_call(adi->runtime);

    uint64_t hardware_address = csap_guest_scratch(adi->runtime, hardware, sizeof(hardware),
                                                   sizeof(hardware));
    uint64_t path_address = csap_guest_scratch(adi->runtime, ADI_STORE_AGENT_SCINFO_PATH,
                                               sizeof(ADI_STORE_AGENT_SCINFO_PATH),
                                               sizeof(ADI_STORE_AGENT_SCINFO_PATH));
    uint64_t context_field = csap_guest_scratch(adi->runtime, NULL, 0, 4);

    if (hardware_address == 0 || path_address == 0 || context_field == 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "allocate FairPlay keybag context inputs");
        return adi_report(adi, error, error_size, "allocate FairPlay keybag context inputs");
    }

    uint64_t arguments[4] = {0, hardware_address, path_address, context_field};
    uint64_t status = 0;
    if (csap_guest_invoke(adi->runtime, ADI_STORE_AGENT_GLOBAL_INIT,
                          arguments, 4, &status) != 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "initialize FairPlay keybag context");
        return adi_report(adi, error, error_size, "initialize FairPlay keybag context");
    }

    if ((int32_t)status != 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "initialize FairPlay keybag context: status %d", (int32_t)status);
        return adi_report(adi, error, error_size, "initialize FairPlay keybag context");
    }

    uint32_t global = 0;
    if (adi_read_u32(adi->runtime, context_field, &global) != 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "read FairPlay keybag context");
        return adi_report(adi, error, error_size, "read FairPlay keybag context");
    }

    if (global == 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "initialize FairPlay keybag context: null context");
        return adi_report(adi, error, error_size, "initialize FairPlay keybag context");
    }

    uint64_t keybag_address = csap_guest_scratch(adi->runtime, keybag, keybag_size, keybag_size);
    if (keybag_address == 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "allocate FairPlay keybag");
        return adi_report(adi, error, error_size, "allocate FairPlay keybag");
    }

    uint64_t keybag_arguments[3] = {global, keybag_address, keybag_size};
    if (csap_guest_invoke(adi->runtime, ADI_KEYBAG_ENTRY, keybag_arguments, 3, &status) != 0) {
        csap_guest_clear_scratch(adi->runtime);
        adi_fail(adi, "import FairPlay keybag");
        return adi_report(adi, error, error_size, "import FairPlay keybag");
    }

    csap_guest_clear_scratch(adi->runtime);

    if ((int32_t)status != 0) {
        adi_fail(adi, "import FairPlay keybag: status %d", (int32_t)status);
        return adi_report(adi, error, error_size, "import FairPlay keybag");
    }

    adi->store_global = global;

    return 0;
}

int csap_adi_exchange_xpc(csap_modern_adi_t* adi,
                          const uint8_t* request, uint64_t request_size,
                          uint8_t** reply, uint64_t* reply_size,
                          char* error, size_t error_size) {
    if (reply != NULL) *reply = NULL;
    if (reply_size != NULL) *reply_size = 0;

    if (adi == NULL || adi->daemon == NULL || adi->daemon_handler == 0) {
        adi_set_error(error, error_size, "modern ADI daemon is unavailable");
        return -1;
    }

    if (request == NULL || request_size == 0 || request_size > ADI_MAX_XPC_REQUEST) {
        adi_set_error(error, error_size, "modern ADI XPC request is invalid");
        return -1;
    }

    csap_shims_t* daemon_shims = csap_guest_shims(adi->daemon);
    csap_shims_clear_xpc_reply(daemon_shims);

    uint64_t request_object = csap_shims_new_xpc_object(daemon_shims, request, request_size, true);
    if (request_object == 0) {
        adi_fail(adi, "modern ADI daemon request object is unavailable");
        return adi_report(adi, error, error_size, "modern ADI daemon request object is unavailable");
    }

    if (adi_invoke_daemon_block(adi, adi->daemon_handler, request_object,
                                error, error_size) != 0) {
        return -1;
    }

    uint64_t size = 0;
    const uint8_t* value = csap_shims_xpc_reply(daemon_shims, &size);
    if (!csap_shims_xpc_replied(daemon_shims) || value == NULL || size == 0) {
        adi_fail(adi, "modern ADI XPC service returned no reply");
        return adi_report(adi, error, error_size, "modern ADI XPC service returned no reply");
    }

    uint8_t* buffer = malloc((size_t)size);
    if (buffer == NULL) {
        adi_fail(adi, "allocate modern ADI XPC reply");
        return adi_report(adi, error, error_size, "allocate modern ADI XPC reply");
    }

    memcpy(buffer, value, (size_t)size);

    if (reply != NULL) {
        *reply = buffer;
    } else {
        free(buffer);
    }
    if (reply_size != NULL) *reply_size = size;

    return 0;
}

int csap_adi_state(csap_modern_adi_t* adi,
                   uint8_t** state, uint64_t* state_size,
                   char* error, size_t error_size) {
    if (state != NULL) *state = NULL;
    if (state_size != NULL) *state_size = 0;

    if (adi == NULL || adi->runtime == NULL) {
        adi_set_error(error, error_size, "modern ADI runtime is unavailable");
        return -1;
    }

    csap_shims_t* shims = csap_guest_shims(adi->daemon);

    uint64_t size = 0;
    const uint8_t* value = csap_shims_adi_file(shims, ADI_STATE_PATH, &size);
    if (value == NULL || size == 0) {
        value = csap_shims_adi_file_by_name(shims, "adi.pb", &size);
    }

    if (value == NULL || size == 0) {
        adi_set_error(error, error_size, "modern ADI state was not created");
        return -1;
    }

    uint8_t* buffer = malloc((size_t)size);
    if (buffer == NULL) {
        adi_set_error(error, error_size, "allocate modern ADI state");
        return -1;
    }

    memcpy(buffer, value, (size_t)size);

    if (state != NULL) {
        *state = buffer;
    } else {
        free(buffer);
    }
    if (state_size != NULL) *state_size = size;

    return 0;
}

void csap_adi_free(void* buffer) {
    free(buffer);
}

void csap_adi_close(csap_modern_adi_t* adi) {
    if (adi == NULL) return;

    if (adi->store_global != 0 && adi->runtime != NULL) {
        uint64_t arguments[1] = {adi->store_global};
        uint64_t status = 0;
        if (csap_guest_invoke(adi->runtime, ADI_STORE_AGENT_GLOBAL_CLOSE,
                              arguments, 1, &status) != 0) {
            fprintf(stderr, "csap modern ADI: close FairPlay keybag context\n");
        } else if ((int32_t)status != 0) {
            fprintf(stderr, "csap modern ADI: close FairPlay keybag context: status %d\n",
                    (int32_t)status);
        }
    }

    csap_guest_close(adi->runtime);
    csap_guest_close(adi->daemon);
    csap_guest_close(adi->fairplay);
    csap_guest_close(adi->kernel);

    free(adi->fairplay_output);
    free(adi->fairplay_indirect);
    free(adi->mach_reply);

    free(adi);
}
