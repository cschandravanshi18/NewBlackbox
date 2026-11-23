#include <sys/system_properties.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include "./xdl.h"
#include <android/log.h>
#include "Dobby/dobby.h"

#define LOG_TAG "VirtualSpoof"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

static char g_custom_uuid[64] = {0};

static bool load_custom_uuid() {
    FILE* f = fopen("/data/user/0/top.niunaijun.blackbox/files/custom_device_uuid.txt", "r");
    if (!f) {
        f = fopen("/data/data/top.niunaijun.blackbox/files/custom_device_uuid.txt", "r");
    }
    if (!f) return false;

    char buf[64] = {0};
    if (fgets(buf, sizeof(buf), f)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' || buf[len - 1] == ' ')) {
            buf[--len] = '\0';
        }
        if (len == 36) {
            strncpy(g_custom_uuid, buf, sizeof(g_custom_uuid) - 1);
            fclose(f);
            return true;
        }
    }
    fclose(f);
    return false;
}

static bool is_uuid_v4_like(const char* str, int nBytes) {
    if (!str) return false;
    size_t len = (nBytes < 0) ? strlen(str) : (size_t)nBytes;
    if (len != 36) return false;
    for (size_t i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (str[i] != '-') return false;
        } else {
            if (!isxdigit((unsigned char)str[i])) return false;
        }
    }
    return true;
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
    for (int i = 0; spoofed_props[i].key != nullptr; ++i) {
        if (strcmp(name, spoofed_props[i].key) == 0) {
            strcpy(value, spoofed_props[i].value);
            return strlen(value);
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
    if (g_custom_uuid[0] != '\0' && is_uuid_v4_like(val, nBytes)) {
        if (strncmp(val, g_custom_uuid, 36) != 0) {
            LOGD("Replacing SQLite bound UUID %.8s... with custom UUID %.8s...", val, g_custom_uuid);
            return orig_sqlite3_bind_text(stmt, idx, g_custom_uuid, 36, (void(*)(void*))-1);
        }
    }
    return orig_sqlite3_bind_text(stmt, idx, val, nBytes, destructor);
}

static void log_http_headers_if_present(const void* buf, size_t len) {
    if (buf == nullptr || len < 15 || len > 8192) return;
    const char* data = (const char*)buf;

    if (memmem(data, len, "User-Agent:", 11) != nullptr ||
        memmem(data, len, "user-agent:", 11) != nullptr) {
        char copy[2048];
        size_t copy_len = len < sizeof(copy) - 1 ? len : sizeof(copy) - 1;
        memcpy(copy, data, copy_len);
        copy[copy_len] = '\0';
        __android_log_print(ANDROID_LOG_INFO, "HttpHeaderLog", "Captured Headers:\n%s", copy);
    }
}

static ssize_t (*orig_send)(int sockfd, const void *buf, size_t len, int flags) = nullptr;
ssize_t my_send(int sockfd, const void *buf, size_t len, int flags) {
    log_http_headers_if_present(buf, len);
    return orig_send(sockfd, buf, len, flags);
}

static ssize_t (*orig_write)(int fd, const void *buf, size_t count) = nullptr;
ssize_t my_write(int fd, const void *buf, size_t count) {
    log_http_headers_if_present(buf, count);
    return orig_write(fd, buf, count);
}

static void hook_sqlite_in_lib(const char* libname) {
    void* handle = xdl_open(libname, XDL_DEFAULT);
    if (!handle) return;

    void* bind_sym = xdl_dsym(handle, "sqlite3_bind_text", nullptr);
    if (bind_sym && orig_sqlite3_bind_text == nullptr) {
        DobbyHook(bind_sym, (void*)my_sqlite3_bind_text, (void**)&orig_sqlite3_bind_text);
        LOGD("VirtualSpoof: Hooked sqlite3_bind_text in %s", libname);
    }
    xdl_close(handle);
}

void install_hooks() {
    if (load_custom_uuid()) {
        LOGD("VirtualSpoof: Loaded custom UUID for SQLite injection (len=36)");
    } else {
        LOGD("VirtualSpoof: No 36-char custom UUID found at init");
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
    LOGD("VirtualSpoof: Property and SQLite UUID hooks loaded");
}

__attribute__((constructor)) void init_virtual_spoof() {
    install_hooks();
}
