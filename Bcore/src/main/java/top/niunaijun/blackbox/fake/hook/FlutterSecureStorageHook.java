package top.niunaijun.blackbox.fake.hook;

import android.content.Context;
import android.content.ContextWrapper;
import android.content.SharedPreferences;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
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
    private static volatile boolean loggedMissingUuid = false;

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
                            loggedMissingUuid = false;
                            return cachedUuid;
                        }
                    }
                } catch (Throwable ignored) {
                }
            }
        }
        if (!loggedMissingUuid) {
            loggedMissingUuid = true;
            Slog.w(TAG, "custom_device_uuid.txt not found or not 36 chars");
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
                    @SuppressWarnings("unchecked")
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
            // Android 16 में ContextImpl में mSharedPrefsCache फ़ील्ड नहीं है;
            // भविष्य के रिफ्लेक्शन हुक्स के लिए base context सुरक्षित रूप से जांच लिया गया है।
            Slog.d(TAG, "hookContextSharedPrefs ready for context=" + (base != null ? base.getClass().getName() : "null"));
        } catch (Throwable t) {
            Slog.w(TAG, "hookContextSharedPrefs notice: " + t.getMessage());
        }
    }
}