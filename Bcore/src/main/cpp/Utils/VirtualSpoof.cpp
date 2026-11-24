#include <sys/system_properties.h>
#include <sys/socket.h>
#include <unistd.h>
#include <dlfcn.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>
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

// स्वयं की लॉग लाइनों और डुप्लिकेट फ़ीडबैक लूप को रोकता है
static bool is_self_log_echo(const char* data, size_t len) {
    if (!data || len == 0) {
        return true;
    }
    const char* noisy_markers[] = {
        "Captured Buffer",
        "VirtualSpoof:",
        "HttpHeaderLog",
        "LOG_FLOWCTRL",
        "DROPPED=="
    };
    for (size_t i = 0; i < sizeof(noisy_markers) / sizeof(noisy_markers[0]); i++) {
        if (memmem(data, len, noisy_markers[i], strlen(noisy_markers[i])) != nullptr) {
            return true;
        }
    }
    return false;
}

static void log_buffer_if_relevant(const void* buf, size_t len, const char* tag_prefix, bool replaced_uuid) {
    if (g_in_log || buf == nullptr || len < 15 || len > 8192) {
        return;
    }
    const char* data = (const char*)buf;
    if (is_self_log_echo(data, len)) {
        return;
    }

    bool hasUserAgent = (memmem(data, len, "User-Agent:", 11) != nullptr ||
                         memmem(data, len, "user-agent:", 11) != nullptr);
    bool hasDeviceUuid = (memmem(data, len, "device_uuid", 11) != nullptr);
    bool hasLoginOrAuth = (memmem(data, len, "password", 8) != nullptr ||
                           memmem(data, len, "login", 5) != nullptr);

    if (hasUserAgent || hasDeviceUuid || hasLoginOrAuth || replaced_uuid) {
        g_in_log = true;
        char copy[1536];
        size_t copy_len = len < sizeof(copy) - 1 ? len : sizeof(copy) - 1;
        memcpy(copy, data, copy_len);
        copy[copy_len] = '\0';
        LOGI("[%s] Buffer (replaced=%d, len=%zu): %s", tag_prefix, replaced_uuid ? 1 : 0, len, copy);
        g_in_log = false;
    }
}

int my_ssl_write(SSL* ssl, const void* buf, int num) {
    if (buf && num > 0 && num <= 32768 && orig_ssl_write) {
        size_t len = (size_t)num;
        bool hasUuid = (memmem(buf, len, "device_uuid", 11) != nullptr);
        bool hasAuth = (memmem(buf, len, "password", 8) != nullptr ||
                        memmem(buf, len, "login", 5) != nullptr);

        if (hasUuid || hasAuth) {
            void* mut = malloc(len + 1);
            if (mut) {
                memcpy(mut, buf, len);
                ((char*)mut)[len] = '\0';
                bool replaced = hasUuid ? replace_any_device_uuid_in_buffer(mut, len) : false;
                log_buffer_if_relevant(mut, len, "SSL_write", replaced);
                int ret = orig_ssl_write(ssl, mut, num);
                free(mut);
                return ret;
            }
        }
    }
    if (orig_ssl_write) {
        return orig_ssl_write(ssl, buf, num);
    }
    return -1;
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
    if (sym) {
        if (DobbyHook(sym, (void*)my_ssl_write, (void**)&orig_ssl_write) == 0) {
            g_ssl_write_hooked = true;
            LOGI("SSL_write debug: Hooked SSL_write in %s at %p", libname, sym);
        } else {
            LOGW("SSL_write debug: DobbyHook failed for SSL_write in %s", libname);
        }
    }
    xdl_close(handle);
}

static void try_hook_flutter_ssl() {
    const char* candidates[] = {"libflutter.so", "libssl.so", "libboringssl.so"};
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        hook_ssl_write_in_lib(candidates[i]);
        if (g_ssl_write_hooked) {
            break;
        }
    }
    if (!g_ssl_write_hooked && !g_ssl_logged_status) {
        g_ssl_logged_status = true;
        LOGW("SSL_write debug: Exported SSL_write symbol not found in loaded SSL libs");
    }
}

void* my_dlopen(const char* filename, int flags) {
    void* res = orig_dlopen ? orig_dlopen(filename, flags) : nullptr;
    if (!g_ssl_write_hooked && filename &&
        (strstr(filename, "flutter") || strstr(filename, "ssl") || strstr(filename, "crypto"))) {
        LOGD("dlopen observed SSL/Flutter lib: %s", filename);
        try_hook_flutter_ssl();
    }
    return res;
}

void* my_android_dlopen_ext(const char* filename, int flags, const void* extinfo) {
    void* res = orig_android_dlopen_ext ? orig_android_dlopen_ext(filename, flags, extinfo) : nullptr;
    if (!g_ssl_write_hooked && filename &&
        (strstr(filename, "flutter") || strstr(filename, "ssl") || strstr(filename, "crypto"))) {
        LOGD("android_dlopen_ext observed SSL/Flutter lib: %s", filename);
        try_hook_flutter_ssl();
    }
    return res;
}

struct SpoofedProp {
    const char* key;
    const char* value;
};

SpoofedProp spoofed_props[] = {
    {"ro.kernel.qemu", "0"},
    {"ro.kernel.android.qemud", ""},
    {"ro.boot.qemu", "0"},
    {nullptr, nullptr}
};

static int (*orig_system_property_get)(const char *name, char *value) = nullptr;

int my_system_property_get(const char *name, char *value) {
    if (name && value) {
        for (int i = 0; spoofed_props[i].key != nullptr; ++i) {
            if (strcmp(name, spoofed_props[i].key) == 0) {
                strcpy(value, spoofed_props[i].value);
                return (int)strlen(value);
            }
        }
    }
    if (orig_system_property_get) {
        return orig_system_property_get(name, value);
    }
    if (value) {
        *value = '\0';
    }
    return 0;
}

static int (*orig_sqlite3_bind_text)(void* stmt, int idx, const char* val, int nBytes, void(*destructor)(void*)) = nullptr;

int my_sqlite3_bind_text(void* stmt, int idx, const char* val, int nBytes, void(*destructor)(void*)) {
    ensure_uuid_loaded();
    if (g_custom_uuid[0] != '\0' && is_uuid_v4_like(val, nBytes)) {
        if (strncmp(val, g_custom_uuid, 36) != 0) {
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
                return orig_sqlite3_bind_text16(stmt, idx, spoof16, 72, (void(*)(void*))-1);
            }
        }
    }
    return orig_sqlite3_bind_text16(stmt, idx, val, nBytes, destructor);
}

static ssize_t (*orig_send)(int sockfd, const void *buf, size_t len, int flags) = nullptr;
ssize_t my_send(int sockfd, const void *buf, size_t len, int flags) {
    bool replaced = false;
    if (buf && len > 0 && len <= 16384 && memmem(buf, len, "device_uuid", 11) != nullptr) {
        void* mut = malloc(len + 1);
        if (mut) {
            memcpy(mut, buf, len);
            ((char*)mut)[len] = '\0';
            replaced = replace_any_device_uuid_in_buffer(mut, len);
            log_buffer_if_relevant(mut, len, "send", replaced);
            ssize_t ret = orig_send(sockfd, mut, len, flags);
            free(mut);
            return ret;
        }
    }
    log_buffer_if_relevant(buf, len, "send", replaced);
    return orig_send(sockfd, buf, len, flags);
}

static ssize_t (*orig_write)(int fd, const void *buf, size_t count) = nullptr;
ssize_t my_write(int fd, const void *buf, size_t count) {
    bool replaced = false;
    if (buf && count > 0 && count <= 16384 && memmem(buf, count, "device_uuid", 11) != nullptr) {
        void* mut = malloc(count + 1);
        if (mut) {
            memcpy(mut, buf, count);
            ((char*)mut)[count] = '\0';
            replaced = replace_any_device_uuid_in_buffer(mut, count);
            log_buffer_if_relevant(mut, count, "write", replaced);
            ssize_t ret = orig_write(fd, mut, count);
            free(mut);
            return ret;
        }
    }
    log_buffer_if_relevant(buf, count, "write", replaced);
    return orig_write(fd, buf, count);
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
        void* prop_target = xdl_dsym(handle, "__system_property_get", nullptr);
        if (prop_target) {
            DobbyHook(prop_target, (void*)my_system_property_get, (void**)&orig_system_property_get);
        }

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
    LOGD("All hooks initialized cleanly");
}

__attribute__((constructor)) void init_virtual_spoof() {
    install_hooks();
}