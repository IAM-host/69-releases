#define _GNU_SOURCE 1
#include "eunora_logi_native.h"

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <jni.h>
#include <link.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#if defined(__ANDROID__)
#include <android/log.h>
#endif

#define EUNORA_EXPORT __attribute__((visibility("default"), used))
#define TARGET_LIBRARY "libtmaplib.so"
#define TARGET_SYMBOL "_Z17get_rooting_checkv"
#define TARGET_PROCESS "com.logisoft.Logi4"
#define TARGET_LEAF_VA ((uintptr_t)0x29fa38u)
#define TARGET_LEAF_SIZE ((uintptr_t)312u)

static const unsigned char expected_build_id[20] = {
    0xf3, 0x3c, 0xa2, 0x21, 0xa4, 0x10, 0x35, 0x7b, 0x0c, 0x01,
    0xf3, 0x55, 0xbb, 0xbc, 0xcf, 0x5d, 0x69, 0x79, 0x0f, 0x57
};
static const unsigned char expected_prologue[16] = {
    0xff, 0x43, 0x02, 0xd1, 0xfd, 0x7b, 0x07, 0xa9,
    0xf4, 0x4f, 0x08, 0xa9, 0xfd, 0xc3, 0x01, 0x91
};

typedef bool (*RootCheck)(void);
_Static_assert(sizeof(RootCheck) == sizeof(void *), "function pointer ABI");
static _Atomic(RootCheck) original_root_check;
static atomic_int current_status = ATOMIC_VAR_INIT(EUNORA_WAITING_FOR_FRAMEWORK);
static atomic_bool normalization_logged;
static pthread_mutex_t install_mutex = PTHREAD_MUTEX_INITIALIZER;
static EunoraHookFunction hook_function;
static EunoraUnhookFunction unhook_function;
static uintptr_t installed_base;
static unsigned char installed_prologue[sizeof(expected_prologue)];
static bool initialized;

/* Host tests replace loader primitives, while running the real validation and
 * installation logic below. No test interface is compiled into Android builds. */
#ifdef EUNORA_HOST_TEST
struct EunoraHostOps {
    ssize_t (*read_cmdline)(char *, size_t);
    void *(*find_symbol)(void *, const char *);
    int (*address_info)(const void *, Dl_info *);
    int (*iterate_modules)(int (*)(struct dl_phdr_info *, size_t, void *), void *);
    void (*log_normalization)(void);
    void (*log_installation)(void);
};
static struct EunoraHostOps host_ops;
#endif

static ssize_t read_cmdline(char *buffer, size_t capacity) {
#ifdef EUNORA_HOST_TEST
    return host_ops.read_cmdline(buffer, capacity);
#else
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t result;
    do {
        result = read(fd, buffer, capacity);
    } while (result < 0 && errno == EINTR);
    close(fd);
    return result;
#endif
}

static void *find_symbol(void *handle, const char *name) {
#ifdef EUNORA_HOST_TEST
    return host_ops.find_symbol(handle, name);
#else
    return dlsym(handle, name);
#endif
}

static int address_info(const void *address, Dl_info *info) {
#ifdef EUNORA_HOST_TEST
    return host_ops.address_info(address, info);
#else
    return dladdr(address, info);
#endif
}

static int iterate_modules(int (*callback)(struct dl_phdr_info *, size_t, void *),
                           void *data) {
#ifdef EUNORA_HOST_TEST
    return host_ops.iterate_modules(callback, data);
#else
    return dl_iterate_phdr(callback, data);
#endif
}

static void log_normalization(void) {
#ifdef EUNORA_HOST_TEST
    host_ops.log_normalization();
#elif defined(__ANDROID__)
    __android_log_write(ANDROID_LOG_INFO, "EUNORA_LOGI_NATIVE",
                        "Verified native rooting result normalized");
#endif
}

static void log_installation(void) {
#ifdef EUNORA_HOST_TEST
    host_ops.log_installation();
#elif defined(__ANDROID__)
    __android_log_write(ANDROID_LOG_INFO, "EUNORA_LOGI_NATIVE",
                        "Verified native rooting leaf hook active");
#endif
}

static bool process_allowed(void) {
    char process[sizeof(TARGET_PROCESS)];
    ssize_t length = read_cmdline(process, sizeof(process));
    /* Include NUL in the comparison: reject process suffixes and truncation. */
    return length == (ssize_t)sizeof(process) &&
           memcmp(process, TARGET_PROCESS, sizeof(process)) == 0;
}

static const char *base_name(const char *path) {
    if (path == NULL) return NULL;
    const char *slash = strrchr(path, '/');
    return slash == NULL ? path : slash + 1;
}

static bool target_name(const char *path) {
    const char *name = base_name(path);
    return name != NULL && strcmp(name, TARGET_LIBRARY) == 0;
}

static bool address_range(uintptr_t base, uintptr_t offset, uintptr_t length,
                          uintptr_t *start, uintptr_t *end) {
    if (offset > UINTPTR_MAX - base) return false;
    *start = base + offset;
    if (length > UINTPTR_MAX - *start) return false;
    *end = *start + length;
    return true;
}

static bool load_contains(const struct dl_phdr_info *info, uintptr_t start,
                          uintptr_t end, ElfW(Word) flags) {
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        uintptr_t segment_start, segment_end;
        if (p->p_type == PT_LOAD && (p->p_flags & flags) == flags &&
            p->p_filesz <= p->p_memsz &&
            address_range((uintptr_t)info->dlpi_addr, p->p_vaddr, p->p_filesz,
                          &segment_start, &segment_end) &&
            start >= segment_start && end <= segment_end) return true;
    }
    return false;
}

static bool verified_build_id(const struct dl_phdr_info *info) {
    unsigned int build_ids = 0;
    bool matching = false;
    for (ElfW(Half) i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type != PT_NOTE) continue;
        uintptr_t start, end;
        if (p->p_filesz > 65536u || p->p_filesz > p->p_memsz ||
            !address_range((uintptr_t)info->dlpi_addr, p->p_vaddr, p->p_filesz,
                           &start, &end) ||
            !load_contains(info, start, end, PF_R)) return false;
        const unsigned char *cursor = (const unsigned char *)start;
        size_t remaining = (size_t)(end - start);
        while (remaining >= sizeof(ElfW(Nhdr))) {
            ElfW(Nhdr) note;
            memcpy(&note, cursor, sizeof(note));
            cursor += sizeof(note);
            remaining -= sizeof(note);
            size_t name_size = note.n_namesz;
            size_t desc_size = note.n_descsz;
            if (name_size > remaining || name_size > SIZE_MAX - 3u ||
                desc_size > SIZE_MAX - 3u) return false;
            size_t aligned_name = (name_size + 3u) & ~(size_t)3u;
            size_t aligned_desc = (desc_size + 3u) & ~(size_t)3u;
            if (aligned_name > remaining ||
                aligned_desc > remaining - aligned_name) return false;
            if (note.n_type == NT_GNU_BUILD_ID && name_size == 4u &&
                memcmp(cursor, "GNU\0", 4u) == 0) {
                ++build_ids;
                matching = desc_size == sizeof(expected_build_id) &&
                    memcmp(cursor + aligned_name, expected_build_id,
                           sizeof(expected_build_id)) == 0;
            }
            cursor += aligned_name + aligned_desc;
            remaining -= aligned_name + aligned_desc;
        }
        /* PT_NOTE tails may contain alignment padding, but not partial notes. */
        for (size_t j = 0; j < remaining; ++j) if (cursor[j] != 0) return false;
    }
    return build_ids == 1u && matching;
}

struct TargetLookup {
    const char *callback_name;
    const Dl_info *symbol_info;
    uintptr_t symbol;
    bool found;
    bool valid;
};

static int validate_module(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    struct TargetLookup *lookup = data;
    if ((uintptr_t)info->dlpi_addr != (uintptr_t)lookup->symbol_info->dli_fbase)
        return 0;
    lookup->found = true;
    if (info->dlpi_phdr == NULL || info->dlpi_phnum == 0 ||
        info->dlpi_phnum > 4096u || !target_name(info->dlpi_name) ||
        !target_name(lookup->symbol_info->dli_fname)) return 1;
    /* An absolute/relative path callback must identify this same loaded image.
     * A basename callback is tied to the image by dladdr and dl_iterate_phdr. */
    if (strchr(lookup->callback_name, '/') != NULL &&
        strcmp(lookup->callback_name, info->dlpi_name) != 0 &&
        strcmp(lookup->callback_name, lookup->symbol_info->dli_fname) != 0)
        return 1;
    uintptr_t leaf_start, leaf_end;
    if (!address_range((uintptr_t)info->dlpi_addr, TARGET_LEAF_VA,
                       TARGET_LEAF_SIZE, &leaf_start, &leaf_end) ||
        lookup->symbol != leaf_start ||
        !load_contains(info, leaf_start, leaf_end, PF_R | PF_X) ||
        !verified_build_id(info)) return 1;
    lookup->valid = true;
    return 1;
}

static int __attribute__((unused))
find_already_loaded(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    bool *found = data;
    if (target_name(info->dlpi_name)) {
        *found = true;
        return 1;
    }
    return 0;
}

static bool normalized_root_check(void) {
    RootCheck original = atomic_load_explicit(&original_root_check, memory_order_acquire);
    if (original == NULL) return true;
    bool result = original();
    int original_errno = errno;
    if (result && !atomic_exchange_explicit(&normalization_logged, true,
                                           memory_order_relaxed)) {
        log_normalization();
    }
    errno = original_errno;
    return false;
}

static void module_loaded(const char *name, void *handle) {
    int incoming_errno = errno;
    bool installed_now = false;
    if (!target_name(name) || handle == NULL) {
        errno = incoming_errno;
        return;
    }
    /* A backend may dlopen recursively during installation. A nested callback
     * must leave the target untouched, rather than wait on our own mutex. */
    if (pthread_mutex_trylock(&install_mutex) != 0) {
        errno = incoming_errno;
        return;
    }
    int status = atomic_load_explicit(&current_status, memory_order_relaxed);
    if (!initialized || (status != EUNORA_WAITING_FOR_TARGET &&
                         status != EUNORA_ACTIVE)) goto done;
    void *symbol = find_symbol(handle, TARGET_SYMBOL);
    Dl_info info;
    memset(&info, 0, sizeof(info));
    if (symbol == NULL || !address_info(symbol, &info) ||
        info.dli_saddr != symbol || info.dli_sname == NULL ||
        strcmp(info.dli_sname, TARGET_SYMBOL) != 0 ||
        !target_name(info.dli_fname)) goto reject;
    struct TargetLookup lookup = {name, &info, (uintptr_t)symbol, false, false};
    iterate_modules(validate_module, &lookup);
    if (!lookup.found || !lookup.valid) goto reject;
    if (installed_base != 0) {
        /* A reload may reuse the old base. Never claim ACTIVE if the bytes
         * installed by our successful hook have disappeared or changed. */
        if (installed_base != (uintptr_t)info.dli_fbase ||
            memcmp(symbol, installed_prologue, sizeof(installed_prologue)) != 0)
            atomic_store_explicit(&current_status, EUNORA_RELOAD_REJECTED,
                                  memory_order_release);
        goto done;
    }
    if (memcmp(symbol, expected_prologue, sizeof(expected_prologue)) != 0)
        goto reject;
    atomic_store_explicit(&current_status, EUNORA_INSTALLING, memory_order_release);
    void *backup = NULL;
    RootCheck replacement = normalized_root_check;
    void *replacement_address;
    memcpy(&replacement_address, &replacement, sizeof(replacement_address));
    int result = hook_function(symbol, replacement_address, &backup);
    if (result != 0 || backup == NULL) {
        /* A successful backend result without a trampoline is unusable. Also
         * roll back a failed operation if it supplied a possible trampoline. */
        int failure = EUNORA_HOOK_FAILED;
        if ((result == 0 || backup != NULL) && unhook_function(symbol) != 0)
            failure = EUNORA_ROLLBACK_FAILED;
        atomic_store_explicit(&current_status, failure, memory_order_release);
        goto done;
    }
    RootCheck original;
    memcpy(&original, &backup, sizeof(original));
    memcpy(installed_prologue, symbol, sizeof(installed_prologue));
    atomic_store_explicit(&original_root_check, original, memory_order_release);
    installed_base = (uintptr_t)info.dli_fbase;
    atomic_store_explicit(&current_status, EUNORA_ACTIVE, memory_order_release);
    installed_now = true;
    goto done;
reject:
    atomic_store_explicit(&current_status, EUNORA_TARGET_REJECTED, memory_order_release);
done:
    pthread_mutex_unlock(&install_mutex);
    if (installed_now) log_installation();
    errno = incoming_errno;
}

EUNORA_EXPORT EunoraModuleLoaded native_init(const EunoraNativeApi *entries) {
    int incoming_errno = errno;
    EunoraModuleLoaded callback = NULL;
    if (pthread_mutex_trylock(&install_mutex) != 0) {
        errno = incoming_errno;
        return NULL;
    }
    if (initialized) {
        int state = atomic_load_explicit(&current_status, memory_order_relaxed);
        if (entries != NULL && (entries->version == 1u || entries->version == 2u) &&
            entries->hook_func != NULL && entries->unhook_func != NULL &&
            entries->hook_func == hook_function &&
            entries->unhook_func == unhook_function &&
            (state == EUNORA_WAITING_FOR_TARGET || state == EUNORA_ACTIVE))
            callback = module_loaded;
        goto done;
    }
    initialized = true;
    if (!process_allowed()) {
        atomic_store_explicit(&current_status, EUNORA_WRONG_PROCESS, memory_order_release);
        goto done;
    }
#if !defined(__aarch64__) && !defined(EUNORA_HOST_TEST)
    (void)entries;
    atomic_store_explicit(&current_status, EUNORA_UNSUPPORTED_ABI, memory_order_release);
    goto done;
#else
    if (entries == NULL || (entries->version != 1u && entries->version != 2u) ||
        entries->hook_func == NULL || entries->unhook_func == NULL) {
        atomic_store_explicit(&current_status, EUNORA_API_REJECTED, memory_order_release);
        goto done;
    }
    bool already_loaded = false;
    iterate_modules(find_already_loaded, &already_loaded);
    if (already_loaded) {
        atomic_store_explicit(&current_status, EUNORA_LATE_UNSUPPORTED, memory_order_release);
        goto done;
    }
    hook_function = entries->hook_func;
    unhook_function = entries->unhook_func;
    atomic_store_explicit(&current_status, EUNORA_WAITING_FOR_TARGET, memory_order_release);
    callback = module_loaded;
#endif
done:
    pthread_mutex_unlock(&install_mutex);
    errno = incoming_errno;
    return callback;
}

EUNORA_EXPORT JNIEXPORT jint JNICALL
Java_com_example_wheelprobe_LogiNativeBridge_status(JNIEnv *env, jclass type) {
    (void)env;
    (void)type;
    return (jint)atomic_load_explicit(&current_status, memory_order_acquire);
}
