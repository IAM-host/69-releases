#ifndef EUNORA_LOGI_NATIVE_H
#define EUNORA_LOGI_NATIVE_H

#include <stdint.h>

/* LSPosed native API v1/v2 share this prefix. The framework owns the entries. */
typedef int (*EunoraHookFunction)(void *, void *, void **);
typedef int (*EunoraUnhookFunction)(void *);
typedef void (*EunoraModuleLoaded)(const char *, void *);
typedef struct {
    uint32_t version;
    EunoraHookFunction hook_func;
    EunoraUnhookFunction unhook_func;
} EunoraNativeApi;

enum EunoraLogiStatus {
    EUNORA_WAITING_FOR_FRAMEWORK = 0,
    EUNORA_WAITING_FOR_TARGET = 1,
    EUNORA_ACTIVE = 2,
    EUNORA_WRONG_PROCESS = 3,
    EUNORA_UNSUPPORTED_ABI = 4,
    EUNORA_API_REJECTED = 5,
    EUNORA_LATE_UNSUPPORTED = 6,
    EUNORA_TARGET_REJECTED = 7,
    EUNORA_HOOK_FAILED = 8,
    EUNORA_ROLLBACK_FAILED = 9,
    EUNORA_RELOAD_REJECTED = 10,
    EUNORA_INSTALLING = 11
};

#endif
