#include <sys/system_properties.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <cstdio>
#include <cctype>
#include "./xdl.h"
#include <android/log.h>
#include <dlfcn.h>
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

static char g_custom_uuid[64] = {0};

void load_custom_uuid() {
    const char* paths[] = {
        "/data/user/0/top.niunaijun.blackbox/files/custom_device_uuid.txt",
        "/data/data/top.niunaijun.blackbox/files/custom_device_uuid.txt",
        nullptr
    };
    for (int i = 0; paths[i] != nullptr; ++i) {
        FILE* f = fopen(paths[i], "r");
        if (f) {
            if (fgets(g_custom_uuid, sizeof(g_custom_uuid), f)) {
                size_t len = strlen(g_custom_uuid);
                while (len > 0 && (g_custom_uuid[len - 1] == '\n' || g_custom_uuid[len - 1] == '\r' || g_custom_uuid[len - 1] == ' ')) {
                    g_custom_uuid[--len] = '\0';
                }
                if (len == 36) {
                    LOGD("Loaded Custom UUID in Native Layer: %s", g_custom_uuid);
                } else {
                    g_custom_uuid[0] = '\0';
                }
            }
            fclose(f);
            if (g_custom_uuid[0] != '\0') break;
        }
    }
}

static bool is_uuid_format(const char* s) {
    for (int i = 0; i < 36; ++i) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') return false;
        } else {
            if (!isxdigit((unsigned char)s[i])) return false;
        }
    }
    return true;
}

static void replace_device_uuid_in_buffer(char* buf, size_t len) {
    if (g_custom_uuid[0] == '\0' || buf == nullptr || len < 45) return;
    const char* key = "device_uuid";
    size_t key_len = 11;
    for (size_t i = 0; i + key_len + 36 <= len; ++i) {
        if (memcmp(buf + i, key, key_len) == 0) {
            for (size_t j = i + key_len; j + 36 <= len && j < i + key_len + 10; ++j) {
                if (is_uuid_format(buf + j)) {
                    memcpy(buf + j, g_custom_uuid, 36);
                    LOGD("Injected Fixed device_uuid into payload: %s", g_custom_uuid);
                    break;
                }
            }
        }
    }
}

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

static int (*orig_SSL_write)(void *ssl, const void *buf, int num) = nullptr;

int my_SSL_write(void *ssl, const void *buf, int num) {
    if (buf != nullptr && num > 40 && g_custom_uuid[0] != '\0') {
        replace_device_uuid_in_buffer((char*)buf, (size_t)num);
    }
    return orig_SSL_write(ssl, buf, num);
}

void install_hooks() {
    load_custom_uuid();

    void* libc_handle = xdl_open("libc.so", XDL_DEFAULT);
    if (libc_handle) {
        void* prop_target = xdl_dsym(libc_handle, "__system_property_get", nullptr);
        if (prop_target) {
            DobbyHook(prop_target, (void*)my_system_property_get, (void**)&orig_system_property_get);
        }
        xdl_close(libc_handle);
    }

    // BoringSSL / OpenSSL (Flutter और Android दोनों का HTTPS पेलोड यहीं से एन्क्रिप्ट होने से पहले गुज़रता है)
    const char* ssl_libs[] = {"libssl.so", "libflutter.so", nullptr};
    for (int i = 0; ssl_libs[i] != nullptr; ++i) {
        void* ssl_handle = xdl_open(ssl_libs[i], XDL_DEFAULT);
        if (ssl_handle) {
            void* ssl_write_sym = xdl_dsym(ssl_handle, "SSL_write", nullptr);
            if (ssl_write_sym && orig_SSL_write == nullptr) {
                if (DobbyHook(ssl_write_sym, (void*)my_SSL_write, (void**)&orig_SSL_write) == 0) {
                    LOGD("Hooked SSL_write in %s successfully!", ssl_libs[i]);
                }
            }
            xdl_close(ssl_handle);
        }
    }
}

__attribute__((constructor)) void init_virtual_spoof()
{
    install_hooks();
    LOGD("VirtualSpoof: All native hooks loaded");
}
