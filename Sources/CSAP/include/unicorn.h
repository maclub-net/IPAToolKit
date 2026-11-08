#ifndef CSAP_UNICORN_H
#define CSAP_UNICORN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// Unicorn 架构和模式常量
#define CSAP_UC_ARCH_X86    4
#define CSAP_UC_MODE_64     8
#define CSAP_UC_ARCH_ARM64  2
#define CSAP_UC_MODE_ARM    0
#define CSAP_UC_PROT_ALL    7  // READ | WRITE | EXEC

// x86-64 寄存器常量
enum csap_uc_reg {
    CSAP_REG_RAX = 35,
    CSAP_REG_RCX = 38,
    CSAP_REG_RDI = 39,
    CSAP_REG_RDX = 40,
    CSAP_REG_RIP = 41,
    CSAP_REG_RSI = 43,
    CSAP_REG_RSP = 44,
    CSAP_REG_R8  = 106,
    CSAP_REG_R9  = 107,
};

// ARM64 寄存器常量（Unicorn 2.1 的 uc_arm64_reg）
enum csap_uc_arm64_reg {
    CSAP_ARM64_REG_X29 = 1,
    CSAP_ARM64_REG_X30 = 2,   // LR
    CSAP_ARM64_REG_SP  = 4,
    CSAP_ARM64_REG_X0  = 199,
    CSAP_ARM64_REG_X1  = 200,
    CSAP_ARM64_REG_X2  = 201,
    CSAP_ARM64_REG_X3  = 202,
    CSAP_ARM64_REG_X4  = 203,
    CSAP_ARM64_REG_X5  = 204,
    CSAP_ARM64_REG_X6  = 205,
    CSAP_ARM64_REG_X7  = 206,
    CSAP_ARM64_REG_X14 = 213,
    CSAP_ARM64_REG_X15 = 214,
    CSAP_ARM64_REG_X16 = 215,
    CSAP_ARM64_REG_V0  = 228,
    CSAP_ARM64_REG_PC  = 260,
};

// Hook 类型
#define CSAP_UC_HOOK_INTR  1
#define CSAP_UC_HOOK_INSN  2
#define CSAP_UC_HOOK_CODE  4
#define CSAP_UC_HOOK_BLOCK 8

// 不透明引擎句柄
typedef struct csap_uc_engine csap_uc_engine_t;

// 代码 hook 回调
typedef void (*csap_uc_hook_cb)(csap_uc_engine_t* uc, uint64_t address, uint32_t size, void* user_data);

// 加载 libunicorn
int csap_uc_load(const char* dylib_path);

// 卸载 libunicorn
void csap_uc_unload(void);

// 引擎生命周期
csap_uc_engine_t* csap_uc_open(int32_t arch, int32_t mode);
int csap_uc_close(csap_uc_engine_t* uc);

// 选择 ARM64 CPU 型号；Unicorn 2.1 默认型号不接受 arm64e 新指令。
int csap_uc_set_max_cpu_model(csap_uc_engine_t* uc);

// 内存操作
int csap_uc_mem_map(csap_uc_engine_t* uc, uint64_t address, uint64_t size, uint32_t perms);
int csap_uc_mem_unmap(csap_uc_engine_t* uc, uint64_t address, uint64_t size);
int csap_uc_mem_read(csap_uc_engine_t* uc, uint64_t address, void* buffer, uint64_t size);
int csap_uc_mem_write(csap_uc_engine_t* uc, uint64_t address, const void* buffer, uint64_t size);

// 寄存器操作
int csap_uc_reg_read(csap_uc_engine_t* uc, int32_t regid, uint64_t* value);
int csap_uc_reg_write(csap_uc_engine_t* uc, int32_t regid, uint64_t value);

// 128 位向量寄存器（ARM64 的 Q 寄存器）
int csap_uc_reg_read128(csap_uc_engine_t* uc, int32_t regid, uint8_t value[16]);
int csap_uc_reg_write128(csap_uc_engine_t* uc, int32_t regid, const uint8_t value[16]);

// 执行控制
int csap_uc_emu_start(csap_uc_engine_t* uc, uint64_t begin, uint64_t end, uint64_t timeout, uint64_t count);
int csap_uc_emu_stop(csap_uc_engine_t* uc);

// Hook 操作
typedef uintptr_t csap_uc_hook_t;
int csap_uc_hook_add(csap_uc_engine_t* uc, csap_uc_hook_t* hook, int32_t type,
                     csap_uc_hook_cb callback, void* user_data,
                     uint64_t begin, uint64_t end);
int csap_uc_hook_del(csap_uc_engine_t* uc, csap_uc_hook_t hook);

// 查询
int csap_uc_query(csap_uc_engine_t* uc, int32_t query_type, uint64_t* result);

// 错误信息
const char* csap_uc_strerror(int32_t code);

#ifdef __cplusplus
}
#endif

#endif // CSAP_UNICORN_H
