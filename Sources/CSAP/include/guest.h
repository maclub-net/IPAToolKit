#ifndef CSAP_GUEST_H
#define CSAP_GUEST_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "unicorn.h"
#include "machimage.h"
#include "shims.h"

#ifdef __cplusplus
extern "C" {
#endif

// ARM64 SAP/Store 访客运行时。
// 对应 Go 侧 internal/sap/machine 的 openRuntime + invoke + scratch。

typedef struct csap_guest csap_guest_t;

// shared-cache 槽位/函数地址到符号名的映射
typedef struct {
    uint64_t    address;
    const char* name;
} csap_guest_symbol_t;

typedef struct {
    const char* name;
    const uint8_t* data;
    uint64_t    size;

    // relocation base；prelinked 为 true 时保留镜像首选地址
    uint64_t    base;
    bool        prelinked;

    // shared cache 元数据
    const csap_guest_symbol_t* prelinked_symbols;
    uint32_t    prelinked_symbol_count;
    const csap_guest_symbol_t* slots;
    uint32_t    slot_count;
    const csap_guest_symbol_t* functions;
    uint32_t    function_count;

    // 非 0 时按 kernel collection 解码指针
    uint64_t    kernel_base;
} csap_guest_image_t;

typedef void (*csap_guest_configure_shims_fn)(csap_shims_t* shims, void* ctx);

typedef struct {
    const uint8_t* corefp_icxs;
    uint64_t    corefp_icxs_size;

    // 从 CoreFP 镜像解析的导出符号
    const char* const* core_export_names;
    uint32_t    core_export_count;

    // 从 AppleMediaServices 镜像解析的入口符号
    const char* const* entry_names;
    uint32_t    entry_count;

    // shims 创建后的附加配置（hostUUID、adi 文件等）
    csap_guest_configure_shims_fn configure_shims;
    void*       configure_context;
} csap_guest_options_t;

// 打开运行时；images[0] 应为 CoreFP，images[1] 为 AppleMediaServices。
csap_guest_t* csap_guest_open(const csap_guest_image_t* images, uint32_t image_count,
                              const csap_guest_options_t* options);

// 查找导出符号（运行时启动后固定）
uint64_t csap_guest_export(csap_guest_t* guest, const char* name);

// 调用访客函数：X0..X7 参数，其余入栈，LR 指向返回地址。
int csap_guest_invoke(csap_guest_t* guest, uint64_t function,
                      const uint64_t* arguments, uint32_t argument_count,
                      uint64_t* result);

// 在当前调用的 scratch 区域预留 reserve_size 字节（data 为 NULL 时清零），
// 并把 data 的前 data_size 字节写入；返回访客地址。
uint64_t csap_guest_scratch(csap_guest_t* guest, const void* data,
                            uint64_t data_size, uint64_t reserve_size);

// 重置 scratch 游标
void csap_guest_begin_call(csap_guest_t* guest);
void csap_guest_clear_scratch(csap_guest_t* guest);

// 访客内存读写
int csap_guest_read(csap_guest_t* guest, uint64_t address, void* buffer, uint64_t size);
int csap_guest_write(csap_guest_t* guest, uint64_t address, const void* buffer, uint64_t size);

// shims 与 fault 状态
csap_shims_t* csap_guest_shims(csap_guest_t* guest);
const char* csap_guest_fault(csap_guest_t* guest);
void csap_guest_reset_fault(csap_guest_t* guest);

void csap_guest_close(csap_guest_t* guest);

#ifdef __cplusplus
}
#endif

#endif // CSAP_GUEST_H
