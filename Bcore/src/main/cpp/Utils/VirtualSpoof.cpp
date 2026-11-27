#include <sys/system_properties.h>
#include <sys/socket.h>
#include <unistd.h>
#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <setjmp.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <cstdint>
#include "./xdl.h"
#include <android/log.h>
#include "Dobby/dobby.h"

#define LOG_TAG "VirtualSpoof"
#define PAYLOAD_TAG "VskPayloadDump"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGP(...) __android_log_print(ANDROID_LOG_INFO, PAYLOAD_TAG, __VA_ARGS__)

typedef struct ssl_st SSL;

static char g_custom_uuid[64] = {0};
static __thread bool g_in_log = false;
static __thread sigjmp_buf g_segv_jmp;
static __thread bool g_segv_guard_active = false;
static bool g_flutter_hooked = false;
static bool g_ssl_hooked = false;
static bool g_sig_installed = false;

static void* (*orig_0x712bbc)(void* a0, void* a1, void* a2, void* a3) = nullptr;
static void* (*orig_0x71fa9c)(void* a0, void* a1, void* a2, void* a3) = nullptr;
static void* (*orig_0x852970)(void* a0, void* a1, void* a2, void* a3) = nullptr;
static void* (*orig_dlopen)(const char* filename, int flags) = nullptr;
static void* (*orig_android_dlopen_ext)(const char* filename, int flags, const void* extinfo) = nullptr;
static int (*orig_sqlite3_bind_text)(void* stmt, int idx, const char* val, int nBytes, void(*destructor)(void*)) = nullptr;
static ssize_t (*orig_send)(int sockfd, const void* buf, size_t len, int flags) = nullptr;
static ssize_t (*orig_write)(int fd, const void* buf, size_t count) = nullptr;
static int (*orig_ssl_write)(SSL* ssl, const void* buf, int num) = nullptr;
static int (*orig_ssl_write_ex)(SSL* ssl, const void* buf, size_t num, size_t* written) = nullptr;

static void segv_safe_handler(int sig) {
    if (g_segv_guard_active) {
        siglongjmp(g_segv_jmp, 1);
    }
    signal(sig, SIG_DFL);
    raise(sig);
}

static void install_segv_guard_once() {
    if (g_sig_installed) {
        return;
    }
    g_sig_installed = true;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = segv_safe_handler;
    sa.sa_flags = SA_NODEFER;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
}

static bool load_custom_uuid() {
    const char* paths[] = {
        "/data/user/0/top.niunaijun.blackbox/files/custom_device_uuid.txt",
        "/data/data/top.niunaijun.blackbox/files/custom_device_uuid.txt",
        "/sdcard/Download/BlackBoxShare/custom_device_uuid.txt",
        "/storage/emulated/0/Download/BlackBoxShare/custom_device_uuid.txt"
    };

    for (size_t idx = 0; idx < sizeof(paths) / sizeof(paths[0]); idx++) {
        FILE* f = fopen(paths[idx], "r");
        if (!f) {
            continue;
        }
        char buf[64] = {0};
        if (fgets(buf, sizeof(buf), f)) {
            size_t len = strlen(buf);
            while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' ' || buf[len - 1] == '\t')) {
                buf[--len] = '\0';
            }
            if (len == 36) {
                char prev[64] = {0};
                memcpy(prev, g_custom_uuid, sizeof(prev));
                memset(g_custom_uuid, 0, sizeof(g_custom_uuid));
                memcpy(g_custom_uuid, buf, 36);
                g_custom_uuid[36] = '\0';
                if (strncmp(prev, g_custom_uuid, 36) != 0) {
                    LOGD("Dynamically loaded custom UUID (len=36): %s", g_custom_uuid);
                }
                fclose(f);
                return true;
            }
        }
        fclose(f);
    }
    return false;
}

static void ensure_uuid_loaded() {
    load_custom_uuid();
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

static const char* find_mem_case_insensitive(const char* haystack, size_t haystack_len, const char* needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0 || haystack_len < needle_len) {
        return nullptr;
    }
    for (size_t i = 0; i + needle_len <= haystack_len; i++) {
        size_t j = 0;
        while (j < needle_len &&
               tolower((unsigned char)haystack[i + j]) == tolower((unsigned char)needle[j])) {
            j++;
        }
        if (j == needle_len) {
            return haystack + i;
        }
    }
    return nullptr;
}

static bool replace_any_device_uuid_in_buffer(void* buf, size_t len) {
    ensure_uuid_loaded();
    if (!buf || len < 36 || g_custom_uuid[0] == '\0') {
        return false;
    }

    char* data = (char*)buf;
    if (len == 36 && is_uuid_v4_like(data, 36)) {
        if (memcmp(data, g_custom_uuid, 36) != 0) {
            memcpy(data, g_custom_uuid, 36);
            return true;
        }
        return false;
    }

    if (len < 42) {
        return false;
    }

    const char* keys[] = {
        "device_uuid", "device-uuid", "deviceuuid",
        "device_id", "device-id", "deviceid", "uuid"
    };

    bool replaced = false;
    for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++) {
        const char* key = keys[k];
        size_t key_len = strlen(key);
        const char* cursor = data;
        size_t remaining = len;

        while (remaining >= key_len + 36) {
            const char* hit = find_mem_case_insensitive(cursor, remaining, key);
            if (!hit) {
                break;
            }
            size_t hit_offset = (size_t)(hit - data);
            size_t search_start = hit_offset + key_len;
            size_t search_end = (search_start + 160 <= len - 36) ? (search_start + 160) : (len - 36);

            for (size_t p = search_start; p <= search_end; p++) {
                if (is_uuid_v4_like(data + p, 36)) {
                    if (memcmp(data + p, g_custom_uuid, 36) != 0) {
                        memcpy(data + p, g_custom_uuid, 36);
                        replaced = true;
                    }
                    break;
                }
            }
            cursor = hit + key_len;
            remaining = len - (size_t)(cursor - data);
        }
    }
    return replaced;
}

static bool is_interesting_http_or_payload(const char* data, size_t len) {
    if (!data || len < 12) {
        return false;
    }
    if (memmem(data, len, PAYLOAD_TAG, strlen(PAYLOAD_TAG)) != nullptr ||
        memmem(data, len, "VirtualSpoof", 12) != nullptr ||
        memmem(data, len, "LOG_FLOWCTRL", 12) != nullptr) {
        return false;
    }

    const char* markers[] = {
        "/attendance-api/", "/auth/login", "POST /", "GET /",
        "HTTP/1.", "HTTP/2", "device_uuid", "device-uuid",
        "deviceId", "device_id", "teacher_code", "password",
        "Authorization:", "x-device"
    };

    for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); i++) {
        if (find_mem_case_insensitive(data, len, markers[i]) != nullptr) {
            return true;
        }
    }
    return false;
}

static bool looks_like_text_buffer(const char* data, size_t len) {
    if (!data || len < 12) {
        return false;
    }
    size_t sample = (len < 128) ? len : 128;
    size_t printable = 0;
    for (size_t i = 0; i < sample; i++) {
        unsigned char c = (unsigned char)data[i];
        if (c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c <= 126)) {
            printable++;
        }
    }
    return (printable * 100) >= (sample * 80);
}

static void dump_payload_chunks(const void* buf, size_t len, const char* source_tag, bool replaced_uuid) {
    if (g_in_log || buf == nullptr || len < 12 || len > 32768) {
        return;
    }

    install_segv_guard_once();
    g_in_log = true;
    g_segv_guard_active = true;

    if (sigsetjmp(g_segv_jmp, 1) == 0) {
        const char* data = (const char*)buf;
        if (is_interesting_http_or_payload(data, len)) {
            LOGP("=== [%s] START (len=%zu, uuid_replaced=%s) ===",
                 source_tag, len, replaced_uuid ? "YES" : "NO");

            const size_t chunk_size = 800;
            for (size_t off = 0; off < len; off += chunk_size) {
                size_t part = (len - off < chunk_size) ? (len - off) : chunk_size;
                char copy[816];
                memcpy(copy, data + off, part);
                copy[part] = '\0';

                for (size_t k = 0; k < part; k++) {
                    unsigned char c = (unsigned char)copy[k];
                    if ((c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c > 0x7E) {
                        copy[k] = '.';
                    }
                }
                LOGP("[%s +%zu]: %s", source_tag, off, copy);
            }
            LOGP("=== [%s] END ===", source_tag);
        }
    }

    g_segv_guard_active = false;
    g_in_log = false;
}

static bool is_plausible_ptr(void* p) {
    uintptr_t v = (uintptr_t)p;
    return v >= 0x10000ULL && v <= 0x7FFFFFFFFFFFULL;
}

static void inspect_multi_buffers(const char* off_name, void* a0, void* a1, void* a2, void* a3) {
    static int total_hits = 0;
    if (g_in_log) {
        return;
    }

    install_segv_guard_once();
    g_in_log = true;
    g_segv_guard_active = true;

    if (sigsetjmp(g_segv_jmp, 1) == 0) {
        void* args[4] = {a0, a1, a2, a3};
        const int pairs[6][2] = {
            {1, 2}, {0, 1}, {2, 3},
            {1, 3}, {0, 2}, {2, 1}
        };

        bool any_dumped = false;
        for (int p = 0; p < 6; p++) {
            void* cand_buf = args[pairs[p][0]];
            size_t cand_len = (size_t)args[pairs[p][1]];
            if (is_plausible_ptr(cand_buf) && cand_len >= 12 && cand_len <= 16384) {
                const char* cdata = (const char*)cand_buf;
                if (is_interesting_http_or_payload(cdata, cand_len)) {
                    total_hits++;
                    LOGP("[%s HIT #%d pair=(x%d,x%d) len=%zu] a0=%p a1=%p a2=%zu a3=%zu",
                         off_name, total_hits, pairs[p][0], pairs[p][1], cand_len,
                         a0, a1, (size_t)a2, (size_t)a3);
                    char tag[64];
                    snprintf(tag, sizeof(tag), "%s:x%d/x%d", off_name, pairs[p][0], pairs[p][1]);
                    g_segv_guard_active = false;
                    g_in_log = false;
                    dump_payload_chunks(cand_buf, cand_len, tag, false);
                    g_in_log = true;
                    g_segv_guard_active = true;
                    any_dumped = true;
                    break;
                }
            }
        }

        if (!any_dumped && total_hits < 15) {
            for (int idx = 0; idx < 4; idx++) {
                if (is_plausible_ptr(args[idx])) {
                    size_t guess_len = 256;
                    for (int l_idx = 0; l_idx < 4; l_idx++) {
                        if (l_idx == idx) continue;
                        size_t v = (size_t)args[l_idx];
                        if (v >= 16 && v <= 4096) {
                            guess_len = v;
                            break;
                        }
                    }
                    if (looks_like_text_buffer((const char*)args[idx], guess_len)) {
                        total_hits++;
                        size_t show = (guess_len < 300) ? guess_len : 300;
                        char preview[312];
                        memcpy(preview, args[idx], show);
                        preview[show] = '\0';
                        for (size_t k = 0; k < show; k++) {
                            unsigned char c = (unsigned char)preview[k];
                            if ((c < 0x20 && c != '\n' && c != '\r' && c != '\t') || c > 0x7E) {
                                preview[k] = '.';
                            }
                        }
                        LOGP("[%s TEXT_CAND #%d x%d len~%zu]: %s",
                             off_name, total_hits, idx, guess_len, preview);
                        break;
                    }
                }
            }
        }
    }

    g_segv_guard_active = false;
    g_in_log = false;
}

void* my_0x712bbc(void* a0, void* a1, void* a2, void* a3) {
    inspect_multi_buffers("0x712bbc", a0, a1, a2, a3);
    return orig_0x712bbc ? orig_0x712bbc(a0, a1, a2, a3) : nullptr;
}

void* my_0x71fa9c(void* a0, void* a1, void* a2, void* a3) {
    inspect_multi_buffers("0x71fa9c", a0, a1, a2, a3);
    return orig_0x71fa9c ? orig_0x71fa9c(a0, a1, a2, a3) : nullptr;
}

void* my_0x852970(void* a0, void* a1, void* a2, void* a3) {
    inspect_multi_buffers("0x852970", a0, a1, a2, a3);
    return orig_0x852970 ? orig_0x852970(a0, a1, a2, a3) : nullptr;
}

#if defined(__aarch64__)
static int phdr_scan_callback(struct dl_phdr_info* info, size_t size, void* data) {
    if (g_flutter_hooked || !info || !info->dlpi_name) {
        return 0;
    }
    if (strstr(info->dlpi_name, "libflutter.so") == nullptr) {
        return 0;
    }

    struct {
        uintptr_t off;
        void* hook_fn;
        void** orig_fn;
        const char* label;
    } targets[] = {
        { 0x712bbcULL, (void*)my_0x712bbc, (void**)&orig_0x712bbc, "s3_pkt_0x712bbc" },
        { 0x71fa9cULL, (void*)my_0x71fa9c, (void**)&orig_0x71fa9c, "tls_rec_0x71fa9c" },
        { 0x852970ULL, (void*)my_0x852970, (void**)&orig_0x852970, "bio_mem_0x852970" }
    };

    int hooked_any = 0;
    for (size_t i = 0; i < sizeof(targets) / sizeof(targets[0]); i++) {
        void* addr = (void*)(info->dlpi_addr + targets[i].off);
        int ret = DobbyHook(addr, targets[i].hook_fn, targets[i].orig_fn);
        LOGI("Flutter multi-hook [%s] base=0x%lx + 0x%lx -> %p, ret=%d, orig=%p",
             targets[i].label, (unsigned long)info->dlpi_addr,
             (unsigned long)targets[i].off, addr, ret, (void*)(*targets[i].orig_fn));
        if (ret == 0 && (*targets[i].orig_fn) != nullptr) {
            hooked_any++;
        }
    }

    if (hooked_any > 0) {
        g_flutter_hooked = true;
        return 1;
    }
    return 0;
}
#endif

static void try_hook_flutter_target() {
#if defined(__aarch64__)
    if (!g_flutter_hooked) {
        xdl_iterate_phdr(phdr_scan_callback, nullptr, XDL_DEFAULT);
    }
#endif
}

static int my_ssl_write(SSL* ssl, const void* buf, int num) {
    bool replaced = false;
    if (buf && num >= 12 && num <= 32768) {
        size_t len = (size_t)num;
        void* mut = malloc(len + 1);
        if (mut) {
            memcpy(mut, buf, len);
            ((char*)mut)[len] = '\0';
            replaced = replace_any_device_uuid_in_buffer(mut, len);
            dump_payload_chunks(mut, len, "ssl_write", replaced);
            int ret = orig_ssl_write ? orig_ssl_write(ssl, mut, num) : -1;
            free(mut);
            return ret;
        }
    }
    if (buf && num > 0) {
        dump_payload_chunks(buf, (size_t)num, "ssl_write", replaced);
    }
    return orig_ssl_write ? orig_ssl_write(ssl, buf, num) : -1;
}

static int my_ssl_write_ex(SSL* ssl, const void* buf, size_t num, size_t* written) {
    bool replaced = false;
    if (buf && num >= 12 && num <= 32768) {
        void* mut = malloc(num + 1);
        if (mut) {
            memcpy(mut, buf, num);
            ((char*)mut)[num] = '\0';
            replaced = replace_any_device_uuid_in_buffer(mut, num);
            dump_payload_chunks(mut, num, "ssl_write_ex", replaced);
            int ret = orig_ssl_write_ex ? orig_ssl_write_ex(ssl, mut, num, written) : 0;
            free(mut);
            return ret;
        }
    }
    if (buf && num > 0) {
        dump_payload_chunks(buf, num, "ssl_write_ex", replaced);
    }
    return orig_ssl_write_ex ? orig_ssl_write_ex(ssl, buf, num, written) : 0;
}

static void hook_ssl_in_lib(const char* libname) {
    void* handle = xdl_open(libname, XDL_DEFAULT);
    if (!handle) {
        return;
    }
    if (orig_ssl_write == nullptr) {
        void* sym_w = xdl_dsym(handle, "SSL_write", nullptr);
        if (sym_w) {
            int r = DobbyHook(sym_w, (void*)my_ssl_write, (void**)&orig_ssl_write);
            LOGI("Hooked SSL_write in %s: ret=%d, orig=%p", libname, r, (void*)orig_ssl_write);
            if (r == 0 && orig_ssl_write != nullptr) {
                g_ssl_hooked = true;
            }
        }
    }
    if (orig_ssl_write_ex == nullptr) {
        void* sym_wex = xdl_dsym(handle, "SSL_write_ex", nullptr);
        if (sym_wex) {
            int r = DobbyHook(sym_wex, (void*)my_ssl_write_ex, (void**)&orig_ssl_write_ex);
            LOGI("Hooked SSL_write_ex in %s: ret=%d, orig=%p", libname, r, (void*)orig_ssl_write_ex);
            if (r == 0 && orig_ssl_write_ex != nullptr) {
                g_ssl_hooked = true;
            }
        }
    }
    xdl_close(handle);
}

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

ssize_t my_send(int sockfd, const void* buf, size_t len, int flags) {
    bool replaced = false;
    if (buf && len >= 36 && len <= 32768) {
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

ssize_t my_write(int fd, const void* buf, size_t count) {
    bool replaced = false;
    if (buf && count >= 36 && count <= 32768) {
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
    xdl_close(handle);
}

void* my_dlopen(const char* filename, int flags) {
    void* res = orig_dlopen ? orig_dlopen(filename, flags) : nullptr;
    if (filename && (strstr(filename, "sqlite") || strstr(filename, "flutter") || strstr(filename, "ssl"))) {
        hook_sqlite_in_lib("libsqlite.so");
        hook_ssl_in_lib("libflutter.so");
        hook_ssl_in_lib("libssl.so");
        try_hook_flutter_target();
    }
    return res;
}

void* my_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    void* res = orig_android_dlopen_ext ? orig_android_dlopen_ext(filename, flags, extinfo) : nullptr;
    if (filename && (strstr(filename, "sqlite") || strstr(filename, "flutter") || strstr(filename, "ssl"))) {
        hook_sqlite_in_lib("libsqlite.so");
        hook_ssl_in_lib("libflutter.so");
        hook_ssl_in_lib("libssl.so");
        try_hook_flutter_target();
    }
    return res;
}

void install_hooks() {
    if (load_custom_uuid()) {
        LOGD("Loaded custom UUID for injection (len=36): %s", g_custom_uuid);
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
    hook_ssl_in_lib("libflutter.so");
    hook_ssl_in_lib("libssl.so");
    try_hook_flutter_target();
    LOGD("Flutter multi-offset & combined hooks initialized cleanly");
}

__attribute__((constructor)) void init_virtual_spoof() {
    install_hooks();
}