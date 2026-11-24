#include <sys/system_properties.h>
#include <sys/socket.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cstdint>
#include "./xdl.h"
#include <android/log.h>
#include "Dobby/dobby.h"

#define LOG_TAG "VirtualSpoof"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

static char g_custom_uuid[64] = {0};
static __thread bool g_in_log = false;
static bool g_ssl_write_hooked = false;
static bool g_ssl_logged_status = false;

typedef struct ssl_st SSL;
static int (*orig_ssl_write)(SSL* ssl, const void* buf, int num) = nullptr;
static void* (*orig_dlopen)(const char* filename, int flags) = nullptr;
static void* (*orig_android_dlopen_ext)(const char* filename, int flags, const void* extinfo) = nullptr;

static bool load_custom_uuid() {
    FILE* f = fopen("/data/user/0/top.niunaijun.blackbox/files/custom_device_uuid.txt", "r");
    if (!f) {
        f = fopen("/data/data/top.niunaijun.blackbox/files/custom_device_uuid.txt", "r");
    }
    if (!f) {
        return false;
    }

    char buf[64] = {0};
    if (fgets(buf, sizeof(buf), f)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' ')) {
            buf[--len] = '\0';
        }
        if (len == 36) {
            memset(g_custom_uuid, 0, sizeof(g_custom_uuid));
            strncpy(g_custom_uuid, buf, 36);
            g_custom_uuid[36] = '\0';
            fclose(f);
            return true;
        }
    }
    fclose(f);
    return false;
}

static void ensure_uuid_loaded() {
    if (g_custom_uuid[0] == '\0') {
        if (load_custom_uuid()) {
            LOGD("Dynamically loaded custom UUID (len=36)");
        }
    }
}

static bool is_uuid_v4_like(const char* str, int nBytes) {
    if (!str) {
        return false;
    }
    size_t len = (nBytes < 0) ? strlen(str) : (size_t)nBytes;
    if (len != 36) {
        return false;
    }
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (str[i] != '-') {
                return false;
            }
        } else {
            if (!isxdigit((unsigned char)str[i])) {
                return false;
            }
        }
    }
    return true;
}

static bool replace_any_device_uuid_in_buffer(void* buf, size_t len) {
    ensure_uuid_loaded();
    if (!buf || len < 48 || g_custom_uuid[0] == '\0') {
        return false;
    }

    char* data = (char*)buf;
    const char* key = "device_uuid";
    size_t key_len = strlen(key);
    bool replaced = false;

    for (size_t i = 0; i + key_len + 36 <= len; i++) {
        if (memcmp(data + i, key, key_len) == 0) {
            size_t search_end = (i + key_len + 64 < len) ? (i + key_len + 64) : (len - 36);
            for (size_t p = i + key_len; p <= search_end; p++) {
                if (is_uuid_v4_like(data + p, 36)) {
                    if (memcmp(data + p, g_custom_uuid, 36) != 0) {
                        memcpy(data + p, g_custom_uuid, 36);
                        replaced = true;
                    }
                    break;
                }
            }
        }
    }
    return replaced;
}

static bool is_logcat_or_self_noise(const char* data, size_t len) {
    if (!data || len == 0) {
        return true;
    }
    const char* noisy_markers[] = {
        "VirtualSpoof",
        "LOG_FLOWCTRL",
        "DROPPED==",
        "NativeCore:",
        "OpenGL ES Shader",
        "SchedAssist:",
        "Choreographer:",
        "VRI[",
        "ViewRootImpl",
        "OplusScrollToTopManager",
        "CustomUuidHook"
    };
    for (size_t i = 0; i < sizeof(noisy_markers) / sizeof(noisy_markers[0]); i++) {
        if (memmem(data, len, noisy_markers[i], strlen(noisy_markers[i])) != nullptr) {
            return true;
        }
    }
    return false;
}

static void dump_payload_chunks(const void* buf, size_t len, const char* tag_prefix, bool replaced_uuid) {
    if (g_in_log || buf == nullptr || len < 10 || len > 16384) {
        return;
    }
    const char* data = (const char*)buf;
    if (is_logcat_or_self_noise(data, len)) {
        return;
    }

    g_in_log = true;
    size_t chunk_size = 512;
    for (size_t off = 0; off < len; off += chunk_size) {
        size_t part = (len - off < chunk_size) ? (len - off) : chunk_size;
        char copy[520];
        memcpy(copy, data + off, part);
        copy[part] = '\0';
        for (size_t k = 0; k < part; k++) {
            unsigned char c = (unsigned char)copy[k];
            if (c < 0x20 && c != '\n' && c != '\r' && c != '\t') {
                copy[k] = '.';
            }
        }
        LOGI("[%s] (rep=%d, total=%zu, off=%zu): %s",
             tag_prefix, replaced_uuid ? 1 : 0, len, off, copy);
    }
    g_in_log = false;
}

int my_ssl_write(SSL* ssl, const void* buf, int num) {
    if (buf && num > 0 && num <= 65536 && orig_ssl_write) {
        size_t len = (size_t)num;
        void* mut = malloc(len + 1);
        if (mut) {
            memcpy(mut, buf, len);
            ((char*)mut)[len] = '\0';
            bool replaced = replace_any_device_uuid_in_buffer(mut, len);
            dump_payload_chunks(mut, len, "SSL_write", replaced);
            int ret = orig_ssl_write(ssl, mut, num);
            free(mut);
            return ret;
        }
    }
    if (orig_ssl_write) {
        return orig_ssl_write(ssl, buf, num);
    }
    return -1;
}

#if defined(__aarch64__)
static uint64_t decode_adrp_addr(uint64_t pc, uint32_t insn) {
    uint64_t immhi = (insn >> 5) & 0x7FFFFULL;
    uint64_t immlo = (insn >> 29) & 0x3ULL;
    int64_t imm = (int64_t)((immhi << 2) | immlo);
    if (imm & (1LL << 20)) {
        imm |= ~((1LL << 21) - 1);
    }
    return (pc & ~0xFFFULL) + (imm << 12);
}

static uintptr_t find_function_start_arm64(const uint8_t* exec_start, size_t exec_len, uintptr_t hit_addr) {
    uintptr_t start_limit = (uintptr_t)exec_start;
    uintptr_t min_scan = (hit_addr > start_limit + 0x600) ? (hit_addr - 0x600) : start_limit;
    for (uintptr_t addr = hit_addr; addr >= min_scan; addr -= 4) {
        uint32_t insn = *(const uint32_t*)addr;
        if ((insn & 0xFFC07FFF) == 0xA9807BFD || (insn & 0xFFC07FFF) == 0xA9007BFD) {
            return addr;
        }
        if ((insn & 0xFF8003FF) == 0xD10003FF && addr >= start_limit + 4) {
            uint32_t prev = *(const uint32_t*)(addr - 4);
            if ((prev & 0xFFC07FFF) == 0xA9807BFD || (prev & 0xFFC07FFF) == 0xA9007BFD) {
                return addr - 4;
            }
        }
    }
    return 0;
}

static uintptr_t scan_exec_for_string_ref_arm64(const uint8_t* rx_start, size_t rx_len, uintptr_t str_va) {
    for (size_t c = 0; c + 8 <= rx_len; c += 4) {
        uintptr_t pc = (uintptr_t)(rx_start + c);
        uint32_t insn1 = *(const uint32_t*)pc;
        if ((insn1 & 0x9F000000) == 0x90000000) {
            uint32_t rd = insn1 & 0x1F;
            uint64_t page = decode_adrp_addr((uint64_t)pc, insn1);

            for (size_t look = 4; look <= 32 && c + look + 4 <= rx_len; look += 4) {
                uint32_t insn2 = *(const uint32_t*)(pc + look);
                uint32_t rn = (insn2 >> 5) & 0x1F;
                if (rn != rd) {
                    continue;
                }
                if ((insn2 & 0xFFC00000) == 0x91000000) {
                    uint64_t imm12 = (insn2 >> 10) & 0xFFFULL;
                    if (insn2 & (1ULL << 22)) {
                        imm12 <<= 12;
                    }
                    if ((uintptr_t)(page + imm12) == str_va) {
                        uintptr_t fn_start = find_function_start_arm64(rx_start, rx_len, pc);
                        if (fn_start != 0) {
                            return fn_start;
                        }
                    }
                }
                if ((insn2 & 0xFFC00000) == 0xF9400000) {
                    uint64_t imm12 = ((insn2 >> 10) & 0xFFFULL) * 8ULL;
                    uintptr_t slot_va = (uintptr_t)(page + imm12);
                    if (slot_va >= (uintptr_t)rx_start - 0x400000 && slot_va <= (uintptr_t)rx_start + rx_len + 0x400000) {
                        const uintptr_t* ptr_slot = (const uintptr_t*)slot_va;
                        if (*ptr_slot == str_va) {
                            uintptr_t fn_start = find_function_start_arm64(rx_start, rx_len, pc);
                            if (fn_start != 0) {
                                return fn_start;
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

static uintptr_t find_ssl_write_via_rodata_arm64(struct dl_phdr_info* info) {
    const uint8_t* ro_start = nullptr;
    size_t ro_len = 0;
    const uint8_t* rx_start = nullptr;
    size_t rx_len = 0;

    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr)* ph = &info->dlpi_phdr[i];
        if (ph->p_type == PT_LOAD) {
            const uint8_t* seg_start = (const uint8_t*)(info->dlpi_addr + ph->p_vaddr);
            if ((ph->p_flags & PF_X) && !rx_start) {
                rx_start = seg_start;
                rx_len = ph->p_memsz;
            } else if (!(ph->p_flags & PF_X) && (ph->p_flags & PF_R)) {
                if (!ro_start || ph->p_memsz > ro_len) {
                    ro_start = seg_start;
                    ro_len = ph->p_memsz;
                }
            }
        }
    }

    if (!ro_start || ro_len < 16 || !rx_start || rx_len < 64) {
        return 0;
    }

    const char* needles[] = {"SSL_write", "bad write retry", "SSL_write:"};
    for (size_t n = 0; n < sizeof(needles) / sizeof(needles[0]); n++) {
        const char* target_str = needles[n];
        size_t target_len = strlen(target_str) + 1;
        for (size_t r = 0; r + target_len <= ro_len; r++) {
            if (memcmp(ro_start + r, target_str, target_len) == 0) {
                uintptr_t str_va = (uintptr_t)(ro_start + r);
                uintptr_t fn = scan_exec_for_string_ref_arm64(rx_start, rx_len, str_va);
                if (fn != 0) {
                    LOGI("SSL_write debug: Matched '%s' at %p -> fn %p", target_str, (void*)str_va, (void*)fn);
                    return fn;
                }
            }
        }
    }
    return 0;
}
#endif

static int phdr_scan_callback(struct dl_phdr_info* info, size_t size, void* data) {
    if (g_ssl_write_hooked || !info || !info->dlpi_name) {
        return 0;
    }
    if (strstr(info->dlpi_name, "libflutter.so") == nullptr &&
        strstr(info->dlpi_name, "libcronet.so") == nullptr) {
        return 0;
    }

#if defined(__aarch64__)
    uintptr_t fn = find_ssl_write_via_rodata_arm64(info);
    if (fn != 0) {
        if (DobbyHook((void*)fn, (void*)my_ssl_write, (void**)&orig_ssl_write) == 0) {
            g_ssl_write_hooked = true;
            LOGI("SSL_write debug: Hooked stripped SSL_write in %s at %p", info->dlpi_name, (void*)fn);
            return 1;
        }
    }
#endif
    return 0;
}

static void hook_ssl_write_in_lib(const char* libname) {
    if (g_ssl_write_hooked || !libname) {
        return;
    }
    void* handle = xdl_open(libname, XDL_DEFAULT);
    if (!handle) {
        return;
    }
    void* sym = xdl_dsym(handle, "SSL_write", nullptr);
    if (!sym) {
        sym = xdl_sym(handle, "SSL_write", nullptr);
    }
    if (sym) {
        if (DobbyHook(sym, (void*)my_ssl_write, (void**)&orig_ssl_write) == 0) {
            g_ssl_write_hooked = true;
            LOGI("SSL_write debug: Hooked SSL_write in %s at %p", libname, sym);
        }
    }
    xdl_close(handle);
}

static void try_hook_flutter_ssl() {
    if (g_ssl_write_hooked) {
        return;
    }
    const char* candidates[] = {"libflutter.so", "libcronet.so", "libssl.so", "libboringssl.so"};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        hook_ssl_write_in_lib(candidates[i]);
        if (g_ssl_write_hooked) {
            return;
        }
    }

    xdl_iterate_phdr(phdr_scan_callback, nullptr, XDL_DEFAULT);

    if (!g_ssl_write_hooked && !g_ssl_logged_status) {
        g_ssl_logged_status = true;
        LOGW("SSL_write debug: SSL_write not found in libflutter.so");
    }
}

static int (*orig_sqlite3_bind_text)(void* stmt, int idx, const char* val, int nBytes, void(*destructor)(void*)) = nullptr;

int my_sqlite3_bind_text(void* stmt, int idx, const char* val, int nBytes, void(*destructor)(void*)) {
    ensure_uuid_loaded();
    if (g_custom_uuid[0] != '\0' && is_uuid_v4_like(val, nBytes)) {
        if (strncmp(val, g_custom_uuid, 36) != 0) {
            LOGI("[sqlite3_bind_text] Replaced UUID at idx=%d", idx);
            return orig_sqlite3_bind_text(stmt, idx, g_custom_uuid, 36, (void(*)(void*))-1);
        }
    }
    return orig_sqlite3_bind_text(stmt, idx, val, nBytes, destructor);
}

static int (*orig_sqlite3_bind_text16)(void* stmt, int idx, const void* val, int nBytes, void(*destructor)(void*)) = nullptr;

int my_sqlite3_bind_text16(void* stmt, int idx, const void* val, int nBytes, void(*destructor)(void*)) {
    ensure_uuid_loaded();
    if (g_custom_uuid[0] != '\0' && val != nullptr) {
        char ascii36[37] = {0};
        const uint16_t* u16 = (const uint16_t*)val;
        size_t maxChars = (nBytes > 0) ? ((size_t)nBytes / 2) : 36;
        if (maxChars == 36) {
            bool ok = true;
            for (size_t i = 0; i < 36; i++) {
                if (u16[i] > 0x7F) {
                    ok = false;
                    break;
                }
                ascii36[i] = (char)u16[i];
            }
            ascii36[36] = '\0';
            if (ok && is_uuid_v4_like(ascii36, 36) && strncmp(ascii36, g_custom_uuid, 36) != 0) {
                uint16_t spoof16[37] = {0};
                for (size_t i = 0; i < 36; i++) {
                    spoof16[i] = (uint16_t)g_custom_uuid[i];
                }
                spoof16[36] = 0;
                LOGI("[sqlite3_bind_text16] Replaced UUID at idx=%d", idx);
                return orig_sqlite3_bind_text16(stmt, idx, spoof16, 72, (void(*)(void*))-1);
            }
        }
    }
    return orig_sqlite3_bind_text16(stmt, idx, val, nBytes, destructor);
}

static ssize_t (*orig_send)(int sockfd, const void *buf, size_t len, int flags) = nullptr;
ssize_t my_send(int sockfd, const void *buf, size_t len, int flags) {
    bool replaced = false;
    if (buf && len > 0 && len <= 16384) {
        void* mut = malloc(len + 1);
        if (mut) {
            memcpy(mut, buf, len);
            ((char*)mut)[len] = '\0';
            replaced = replace_any_device_uuid_in_buffer(mut, len);
            dump_payload_chunks(mut, len, "send", replaced);
            ssize_t ret = orig_send(sockfd, mut, len, flags);
            free(mut);
            return ret;
        }
    }
    dump_payload_chunks(buf, len, "send", replaced);
    return orig_send ? orig_send(sockfd, buf, len, flags) : -1;
}

static ssize_t (*orig_write)(int fd, const void *buf, size_t count) = nullptr;
ssize_t my_write(int fd, const void *buf, size_t count) {
    bool replaced = false;
    if (buf && count > 0 && count <= 16384) {
        void* mut = malloc(count + 1);
        if (mut) {
            memcpy(mut, buf, count);
            ((char*)mut)[count] = '\0';
            replaced = replace_any_device_uuid_in_buffer(mut, count);
            dump_payload_chunks(mut, count, "write", replaced);
            ssize_t ret = orig_write(fd, mut, count);
            free(mut);
            return ret;
        }
    }
    dump_payload_chunks(buf, count, "write", replaced);
    return orig_write ? orig_write(fd, buf, count) : -1;
}

static void hook_sqlite_in_lib(const char* libname) {
    void* handle = xdl_open(libname, XDL_DEFAULT);
    if (!handle) {
        return;
    }

    void* bind_sym = xdl_dsym(handle, "sqlite3_bind_text", nullptr);
    if (bind_sym && orig_sqlite3_bind_text == nullptr) {
        DobbyHook(bind_sym, (void*)my_sqlite3_bind_text, (void**)&orig_sqlite3_bind_text);
    }

    void* bind16_sym = xdl_dsym(handle, "sqlite3_bind_text16", nullptr);
    if (bind16_sym && orig_sqlite3_bind_text16 == nullptr) {
        DobbyHook(bind16_sym, (void*)my_sqlite3_bind_text16, (void**)&orig_sqlite3_bind_text16);
    }

    xdl_close(handle);
}

void* my_dlopen(const char* filename, int flags) {
    void* res = orig_dlopen ? orig_dlopen(filename, flags) : nullptr;
    if (filename && (strstr(filename, "sqlite") || strstr(filename, "flutter") || strstr(filename, "cronet") || strstr(filename, "ssl") || strstr(filename, "crypto"))) {
        hook_sqlite_in_lib("libsqlite.so");
        try_hook_flutter_ssl();
    }
    return res;
}

void* my_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    void* res = orig_android_dlopen_ext ? orig_android_dlopen_ext(filename, flags, extinfo) : nullptr;
    if (filename && (strstr(filename, "sqlite") || strstr(filename, "flutter") || strstr(filename, "cronet") || strstr(filename, "ssl") || strstr(filename, "crypto"))) {
        hook_sqlite_in_lib("libsqlite.so");
        try_hook_flutter_ssl();
    }
    return res;
}

void install_hooks() {
    if (load_custom_uuid()) {
        LOGD("Loaded custom UUID for injection (len=36)");
    } else {
        LOGW("No 36-char custom UUID found at init");
    }

    void* dl_handle = xdl_open("libdl.so", XDL_DEFAULT);
    if (dl_handle) {
        void* dlopen_sym = xdl_dsym(dl_handle, "dlopen", nullptr);
        if (dlopen_sym) {
            DobbyHook(dlopen_sym, (void*)my_dlopen, (void**)&orig_dlopen);
        }
        void* ext_sym = xdl_dsym(dl_handle, "android_dlopen_ext", nullptr);
        if (ext_sym) {
            DobbyHook(ext_sym, (void*)my_android_dlopen_ext, (void**)&orig_android_dlopen_ext);
        }
        xdl_close(dl_handle);
    }

    void* handle = xdl_open("libc.so", XDL_DEFAULT);
    if (handle) {
        void* send_target = xdl_dsym(handle, "send", nullptr);
        if (send_target) {
            DobbyHook(send_target, (void*)my_send, (void**)&orig_send);
        }

        void* write_target = xdl_dsym(handle, "write", nullptr);
        if (write_target) {
            DobbyHook(write_target, (void*)my_write, (void**)&orig_write);
        }
        xdl_close(handle);
    }

    hook_sqlite_in_lib("libsqlite.so");
    try_hook_flutter_ssl();
    LOGD("Combined hooks initialized cleanly");
}

__attribute__((constructor)) void init_virtual_spoof() {
    install_hooks();
}