#ifndef CSAP_SHIMS_H
#define CSAP_SHIMS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "unicorn.h"
#include "machimage.h"

#ifdef __cplusplus
extern "C" {
#endif

// 与 Go 侧 machine.shimBase 保持一致，避免与 modern ADID 的基址冲突。
#define CSAP_SHIM_BASE      0x00007ff880000000ULL
#define CSAP_SHIM_CODE_SIZE 0x0000000000080000ULL
#define CSAP_SHIM_SIZE      0x0000000000100000ULL
#define CSAP_SHIM_SLOT_SIZE 16

// 堆和栈地址
#define CSAP_HEAP_BASE      0x0000400000000000ULL
#define CSAP_HEAP_SIZE      (64ULL << 20)
#define CSAP_STACK_BASE     0x0000500000000000ULL
#define CSAP_STACK_SIZE     (8ULL << 20)
#define CSAP_SCRATCH_BASE   0x0000300000000000ULL
#define CSAP_SCRATCH_SIZE   (32ULL << 20)
#define CSAP_RETURN_ADDRESS 0x0000000100000000ULL

#define CSAP_MAX_GUEST_TRANSFER (64ULL << 20)

// 前向声明
typedef struct csap_shims csap_shims_t;

// Shim handler 回调
// 返回 0 表示成功，非 0 表示失败
typedef int (*csap_shim_handler_t)(csap_shims_t* s, void* ctx);

// Shim ABI 模式
typedef enum {
    CSAP_SHIM_ABI_X86_64 = 0,
    CSAP_SHIM_ABI_ARM64  = 1,
} csap_shim_abi_t;

// CoreFP 导出符号
typedef struct {
    const char* name;
    uint64_t    address;
} csap_core_export_t;

// 创建 shims
// core_exports: CoreFP 镜像的导出符号表（用于解析内部符号）
// icxs: CoreFP.icxs 数据
csap_shims_t* csap_shims_create(csap_uc_engine_t* engine,
                                csap_macho_image_t* corefp_image,
                                const uint8_t* icxs, uint64_t icxs_size);

// 创建 shims（显式 ABI 与 CoreFP 导出表），供 ARM64 Store 运行时使用
csap_shims_t* csap_shims_create_ex(csap_uc_engine_t* engine, csap_shim_abi_t abi,
                                   const csap_core_export_t* core_exports, uint32_t core_export_count,
                                   const uint8_t* icxs, uint64_t icxs_size);

// 查询 ABI
bool csap_shims_is_arm64(csap_shims_t* s);

// CoreFP 导出符号查找
uint64_t csap_shims_core_export(csap_shims_t* s, const char* name);

// 注册零返回值别名
int csap_shims_add_zero_return_alias(csap_shims_t* s, const char* name);

// 关闭 shims
void csap_shims_close(csap_shims_t* s);

// 解析符号地址（如果不存在，创建一个默认的 "unsupported" shim）
uint64_t csap_shims_resolve(csap_shims_t* s, const char* name);

// 查找已注册符号地址，不存在返回 0
uint64_t csap_shims_symbol(csap_shims_t* s, const char* name);

// 添加一个 shim 函数
uint64_t csap_shims_add_function(csap_shims_t* s, const char* name,
                                 csap_shim_handler_t handler, void* ctx);

// 添加一个 shim 数据块
uint64_t csap_shims_add_data(csap_shims_t* s, const char* name,
                             const void* data, uint64_t size);

// 获取 fault 信息
const char* csap_shims_fault(csap_shims_t* s);
void csap_shims_reset_fault(csap_shims_t* s);

// ==================== 辅助函数 ====================

// 读取函数参数（System V AMD64 ABI）
// index 0-5: RDI, RSI, RDX, RCX, R8, R9
// index >= 6: 栈
int csap_shims_arg(csap_shims_t* s, int index, uint64_t* value);

// 设置返回值 (RAX)
int csap_shims_set_result(csap_shims_t* s, uint64_t value);

// 内存读写辅助
int csap_shims_read_u32(csap_shims_t* s, uint64_t addr, uint32_t* value);
int csap_shims_write_u32(csap_shims_t* s, uint64_t addr, uint32_t value);
int csap_shims_read_u64(csap_shims_t* s, uint64_t addr, uint64_t* value);
int csap_shims_write_u64(csap_shims_t* s, uint64_t addr, uint64_t value);
int csap_shims_read_mem(csap_shims_t* s, uint64_t addr, void* buf, uint64_t size);
int csap_shims_write_mem(csap_shims_t* s, uint64_t addr, const void* buf, uint64_t size);

// 读取 C 字符串（最多 max_len 字节）
int csap_shims_read_cstring(csap_shims_t* s, uint64_t addr, char* buf, size_t max_len);

// 获取 errno
uint64_t csap_shims_errno(csap_shims_t* s);
void csap_shims_set_errno(csap_shims_t* s, uint64_t value);

// 获取 engine
csap_uc_engine_t* csap_shims_engine(csap_shims_t* s);

// 平台服务状态访问
uint64_t csap_shims_errno_addr(csap_shims_t* s);
void csap_shims_set_errno_addr(csap_shims_t* s, uint64_t addr);
uint64_t csap_shims_icxs_offset(csap_shims_t* s);
void csap_shims_set_icxs_offset(csap_shims_t* s, uint64_t offset);
uint32_t csap_shims_iterator(csap_shims_t* s);
void csap_shims_set_iterator(csap_shims_t* s, uint32_t iter);
const uint8_t* csap_shims_icxs(csap_shims_t* s);
uint64_t csap_shims_icxs_size(csap_shims_t* s);
csap_macho_image_t* csap_shims_corefp(csap_shims_t* s);

// ARM64 Store 运行时状态
void csap_shims_set_host_uuid(csap_shims_t* s, const uint8_t uuid[16]);
int csap_shims_host_uuid(csap_shims_t* s, uint8_t out[16]);
void* csap_shims_platform_state(csap_shims_t* s);
void csap_shims_set_platform_state(csap_shims_t* s, void* state);

// ==================== ARM64 Store 平台服务状态 ====================

// FairPlay IOKit 结构化方法调用
typedef struct {
    // 输入
    const uint8_t* input;
    uint64_t       input_size;
    const uint8_t* indirect;
    uint64_t       indirect_size;
    int            output_capacity;

    // 输出；指针由 handler 持有，至少保持到下一次调用。
    const uint8_t* output;
    uint64_t       output_size;
    const uint8_t* indirect_output;
    uint64_t       indirect_output_size;
    int32_t        code;
} csap_shims_fairplay_call_t;

typedef int (*csap_shims_fairplay_handler_t)(void* ctx, csap_shims_fairplay_call_t* call);

// Mach 内核 RPC
typedef struct {
    const uint8_t* request;
    uint64_t       request_size;
    int            receive_size;

    const uint8_t* reply;
    uint64_t       reply_size;
} csap_shims_mach_rpc_call_t;

typedef int (*csap_shims_mach_rpc_handler_t)(void* ctx, csap_shims_mach_rpc_call_t* call);

void csap_shims_set_fairplay_handler(csap_shims_t* s, csap_shims_fairplay_handler_t handler, void* ctx);
csap_shims_fairplay_handler_t csap_shims_fairplay_handler(csap_shims_t* s);
void* csap_shims_fairplay_context(csap_shims_t* s);

void csap_shims_set_mach_rpc_handler(csap_shims_t* s, csap_shims_mach_rpc_handler_t handler, void* ctx);
csap_shims_mach_rpc_handler_t csap_shims_mach_rpc_handler(csap_shims_t* s);
void* csap_shims_mach_rpc_context(csap_shims_t* s);

// 运行循环与零返回值别名
void csap_shims_set_pause_run_loop(csap_shims_t* s, bool pause);
bool csap_shims_pause_run_loop(csap_shims_t* s);
int csap_shims_add_zero_return_aliases(csap_shims_t* s, const char* const* names, uint32_t count);

// dispatch_once / pthread_once 回调
int csap_shims_invoke_callback(csap_shims_t* s, uint64_t initializer);
int csap_shims_complete_callback(csap_shims_t* s);

// XPC 对象表
uint64_t csap_shims_new_xpc_object(csap_shims_t* s, const void* data, uint64_t size, bool has_data);
void csap_shims_set_xpc_object_data(csap_shims_t* s, uint64_t object, const void* data, uint64_t size);
uint64_t csap_shims_xpc_object_address(csap_shims_t* s, uint64_t object,
                                       uint64_t* size, bool* has_data);
const uint8_t* csap_shims_xpc_object_data(csap_shims_t* s, uint64_t object, uint64_t* size);
bool csap_shims_xpc_object_exists(csap_shims_t* s, uint64_t object);

void csap_shims_set_xpc_sync_reply(csap_shims_t* s, const void* data, uint64_t size);
const uint8_t* csap_shims_xpc_sync_reply(csap_shims_t* s, uint64_t* size);
void csap_shims_set_xpc_reply(csap_shims_t* s, const void* data, uint64_t size, bool replied);
const uint8_t* csap_shims_xpc_reply(csap_shims_t* s, uint64_t* size);
bool csap_shims_xpc_replied(csap_shims_t* s);
void csap_shims_clear_xpc_reply(csap_shims_t* s);

// 最近一次 xpc_dictionary_set_data 的内容
const uint8_t* csap_shims_xpc_data(csap_shims_t* s, uint64_t* size);
void csap_shims_clear_xpc_data(csap_shims_t* s);

void csap_shims_set_xpc_event_handler(csap_shims_t* s, uint64_t address);
uint64_t csap_shims_xpc_event_handler(csap_shims_t* s);

// Mach 端口状态
void csap_shims_set_mach_port(csap_shims_t* s, uint64_t callback, uint64_t context, uint64_t info);
uint64_t csap_shims_mach_port_callback(csap_shims_t* s);
uint64_t csap_shims_mach_port_context(csap_shims_t* s);
uint64_t csap_shims_mach_port_info(csap_shims_t* s);

void csap_shims_set_mach_message_reply(csap_shims_t* s, const void* data, uint64_t size);
const uint8_t* csap_shims_mach_message_reply(csap_shims_t* s, uint64_t* size);
void csap_shims_clear_mach_message_reply(csap_shims_t* s);

// ADI 状态文件（/var/db/fpsd/adi/adi.pb 的虚拟重定向）
bool csap_shims_is_adi_state_path(const char* path);
int csap_shims_set_adi_file(csap_shims_t* s, const char* path, const void* data, uint64_t size);
void csap_shims_remove_adi_file(csap_shims_t* s, const char* path);
bool csap_shims_has_adi_file(csap_shims_t* s, const char* path);
const uint8_t* csap_shims_adi_file(csap_shims_t* s, const char* path, uint64_t* size);
const uint8_t* csap_shims_adi_file_by_name(csap_shims_t* s, const char* base_name, uint64_t* size);
void csap_shims_set_adi_path(csap_shims_t* s, const char* path);
const char* csap_shims_adi_path(csap_shims_t* s);
void csap_shims_set_adi_offset(csap_shims_t* s, uint64_t offset);
uint64_t csap_shims_adi_offset(csap_shims_t* s);

// 内核服务与缓冲区 vtable（IOAESAccelerator / IOBufferMemoryDescriptor）
uint64_t csap_shims_kernel_service(csap_shims_t* s);
void csap_shims_set_kernel_service(csap_shims_t* s, uint64_t address);
uint64_t csap_shims_buffer_vtable(csap_shims_t* s);
void csap_shims_set_buffer_vtable(csap_shims_t* s, uint64_t address);

// ==================== 堆管理 ====================

uint64_t csap_shims_allocate(csap_shims_t* s, uint64_t size);
uint64_t csap_shims_allocate_aligned(csap_shims_t* s, uint64_t size, uint64_t alignment);
int csap_shims_release(csap_shims_t* s, uint64_t address);
uint64_t csap_shims_allocation_size(csap_shims_t* s, uint64_t address);

// ==================== 服务注册 ====================

// 注册内存服务 (malloc, free, memcpy, etc.)
int csap_shims_register_memory_services(csap_shims_t* s);

// 注册平台服务 (CoreFoundation, IOKit, POSIX, etc.)
int csap_shims_register_platform_services(csap_shims_t* s);

#ifdef __cplusplus
}
#endif

#endif // CSAP_SHIMS_H
