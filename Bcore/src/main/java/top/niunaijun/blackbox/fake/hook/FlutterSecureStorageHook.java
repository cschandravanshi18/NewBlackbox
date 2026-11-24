package top.niunaijun.blackbox.fake.hook;

import android.content.SharedPreferences;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Method;

import top.niunaijun.blackbox.app.BActivityThread;
import top.niunaijun.blackbox.utils.Slog;

public class FlutterSecureStorageHook {
    public static final String TAG = "FlutterSecureHook";
    private static volatile String cachedUuid = null;
    private static volatile long lastLoadTime = 0;

    private static String getCustomUuid() {
        long now = System.currentTimeMillis();
        if (cachedUuid != null && (now - lastLoadTime) < 3000) {
            return cachedUuid;
        }
        lastLoadTime = now;

        File[] files = new File[] {
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

    public static void install() {
        try {
            Class<?> spImplClass = Class.forName("android.app.SharedPreferencesImpl");
            Method getStringMethod = spImplClass.getDeclaredMethod("getString", String.class, String.class);
            getStringMethod.setAccessible(true);

            HookManager.get().addHook(getStringMethod, new MethodHook() {
                @Override
                protected Object hook(Object who, Method method, Object... args) throws Throwable {
                    String pkg = BActivityThread.getAppPackageName();
                    if (pkg != null && !"com.vsk_teacher_attendance".equals(pkg)) {
                        return method.invoke(who, args);
                    }
                    if (args != null && args.length >= 1 && args[0] instanceof String) {
                        String key = (String) args[0];
                        if (key.contains("device_uuid")) {
                            String customUuid = getCustomUuid();
                            Object origVal = method.invoke(who, args);
                            if (customUuid != null) {
                                Slog.d(TAG, "Intercepted key=" + key + " origLen=" +
                                        (origVal != null ? origVal.toString().length() : 0) +
                                        " -> overriding with custom UUID");
                                return customUuid;
                            }
                        }
                    }
                    return method.invoke(who, args);
                }
            });
            Slog.d(TAG, "FlutterSecureStorageHook installed on SharedPreferencesImpl.getString");
        } catch (Throwable t) {
            Slog.w(TAG, "FlutterSecureStorageHook install failed: " + t.getMessage());
        }
    }
}