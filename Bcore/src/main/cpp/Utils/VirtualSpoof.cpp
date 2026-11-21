#include <sys/system_properties.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include "./xdl.h"
#include <android/log.h>
#include "Dobby/dobby.h"

#define LOG_TAG "VirtualSpoof"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)

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

void install_hooks() {
    void* handle = xdl_open("libc.so", XDL_DEFAULT);
    if (!handle) return;

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
    LOGD("VirtualSpoof: Property and HTTP Header Logger hooks loaded");
}

__attribute__((constructor)) void init_virtual_spoof()
{
    install_hooks();
}
