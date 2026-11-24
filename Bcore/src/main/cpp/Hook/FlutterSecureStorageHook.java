package top.niunaijun.blackbox.fake.hook;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;
import android.util.ArrayMap;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.util.HashMap;
import java.util.Map;

import top.niunaijun.blackbox.app.BActivityThread;
import top.niunaijun.blackbox.utils.Slog;

public class FlutterSecureStorageHook {
    public static final String TAG = "FlutterSecureHook";
    private static volatile String cachedUuid = null;
    private static volatile long lastLoadTime = 0;

    public static String getCustomUuid() {
        long now = System.currentTimeMillis();
        if (cachedUuid != null && (now - lastLoadTime) < 3000) {
            return cachedUuid;
        }
        lastLoadTime = now;

        File[] files = new File[]{
                new File("/data/user/0/top.niunaijun.blackbox/files/custom_device_uuid.txt"),
                new File("/data/data/top.niunaijun.blackbox/files/custom_device_uuid.txt")
        };
        for (File f : files) {
            if (f != null && f.exists() && f.isFile() && f.canRead()) {
                try (BufferedReader br = new BufferedReader(new FileReader(f))) {
                    String line = br.readLine();
                    if (line != null) {
                        line = line.trim();
                        if (line.length() == 36) {
                            cachedUuid = line;
                            return cachedUuid;
                        }
                    }
                } catch (Throwable ignored) {
                }
            }
        }
        return null;
    }

    public static SharedPreferences wrapSharedPreferences(final SharedPreferences base) {
        if (base == null) {
            return null;
        }
        if (Proxy.isProxyClass(base.getClass())) {
            return base;
        }
        return (SharedPreferences) Proxy.newProxyInstance(
                SharedPreferences.class.getClassLoader(),
                new Class<?>[]{SharedPreferences.class},
                new InvocationHandler() {
                    @Override
                    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
                        String name = method.getName();
                        String pkg = BActivityThread.getAppPackageName();
                        boolean isTargetApp = (pkg == null || "com.vsk_teacher_attendance".equals(pkg));

                        if (isTargetApp && "getString".equals(name) && args != null && args.length >= 1 && args[0] instanceof String) {
                            String key = (String) args[0];
                            if (key.contains("device_uuid")) {
                                String customUuid = getCustomUuid();
                                Object origVal = method.invoke(base, args);
                                if (customUuid != null) {
                                    Slog.d(TAG, "getString intercepted key=" + key + " origLen=" +
                                            (origVal != null ? origVal.toString().length() : 0) +
                                            " -> returning custom UUID");
                                    return customUuid;
                                }
                            }
                        } else if (isTargetApp && "getAll".equals(name)) {
                            Object res = method.invoke(base, args);
                            if (res instanceof Map) {
                                String customUuid = getCustomUuid();
                                if (customUuid != null) {
                                    Map<String, Object> copy = new HashMap<>((Map<String, Object>) res);
                                    for (String k : copy.keySet()) {
                                        if (k != null && k.contains("device_uuid")) {
                                            Slog.d(TAG, "getAll intercepted key=" + k + " -> overriding with custom UUID");
                                            copy.put(k, customUuid);
                                        }
                                    }
                                    return copy;
                                }
                            }
                            return res;
                        }
                        return method.invoke(base, args);
                    }
                }
        );
    }

    @SuppressWarnings("unchecked")
    public static void hookContextSharedPrefs(Context context) {
        if (context == null) {
            return;
        }
        try {
            int deep = 0;
            Context base = context;
            while (base instanceof ContextWrapper && deep < 10) {
                Context next = ((ContextWrapper) base).getBaseContext();
                if (next == null || next == base) {
                    break;
                }
                base = next;
                deep++;
            }

            Class<?> contextImplClass = Class.forName("android.app.ContextImpl");
            if (!contextImplClass.isInstance(base)) {
                return;
            }

            Field cacheField = contextImplClass.getDeclaredField("mSharedPrefsCache");
            cacheField.setAccessible(true);
            Object cacheObj = cacheField.get(base);
            if (cacheObj instanceof ArrayMap) {
                ArrayMap<File, SharedPreferences> originalMap = (ArrayMap<File, SharedPreferences>) cacheObj;
                if (!(originalMap instanceof WrappedSharedPrefsMap)) {
                    WrappedSharedPrefsMap wrappedMap = new WrappedSharedPrefsMap();
                    wrappedMap.putAll(originalMap);
                    cacheField.set(base, wrappedMap);
                    Slog.d(TAG, "Hooked ContextImpl.mSharedPrefsCache successfully");
                }
            }
        } catch (Throwable t) {
            Slog.w(TAG, "hookContextSharedPrefs failed: " + t.getMessage());
        }
    }

    private static class WrappedSharedPrefsMap extends ArrayMap<File, SharedPreferences> {
        @Override
        public SharedPreferences get(Object key) {
            SharedPreferences sp = super.get(key);
            if (sp != null) {
                SharedPreferences wrapped = wrapSharedPreferences(sp);
                if (wrapped != sp) {
                    super.put((File) key, wrapped);
                }
                return wrapped;
            }
            return null;
        }

        @Override
        public SharedPreferences put(File key, SharedPreferences value) {
            return super.put(key, wrapSharedPreferences(value));
        }
    }
}