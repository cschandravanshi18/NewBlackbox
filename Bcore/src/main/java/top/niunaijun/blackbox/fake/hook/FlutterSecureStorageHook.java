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
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import top.niunaijun.blackbox.app.BActivityThread;
import top.niunaijun.blackbox.utils.Slog;

public class FlutterSecureStorageHook {
    public static final String TAG = "FlutterSecureHook";
    public static final String TARGET_PKG = "com.vsk_teacher_attendance";
    private static final Pattern UUID_V4_PATTERN = Pattern.compile(
            "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );

    private static volatile String cachedUuid = null;
    private static volatile long lastLoadTime = 0;
    private static volatile boolean loggedMissingUuid = false;

    public static boolean isTargetPackage() {
        String pkg = BActivityThread.getAppPackageName();
        return pkg == null || TARGET_PKG.equals(pkg);
    }

    public static String getCustomUuid() {
        long now = System.currentTimeMillis();
        if (cachedUuid != null && (now - lastLoadTime) < 2000) {
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
                        if (line.length() == 36 && UUID_V4_PATTERN.matcher(line).matches()) {
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
            Slog.w(TAG, "custom_device_uuid.txt not found or not valid 36-char UUID");
        }
        return null;
    }

    public static byte[] replaceUuidBytesIfNeeded(byte[] input) {
        if (!isTargetPackage() || input == null || input.length != 36) {
            return input;
        }
        String customUuid = getCustomUuid();
        if (customUuid == null) {
            return input;
        }
        try {
            String str = new String(input, StandardCharsets.UTF_8);
            if (UUID_V4_PATTERN.matcher(str).matches() && !str.equalsIgnoreCase(customUuid)) {
                Slog.d(TAG, "Replaced 36-byte UUID payload in crypto/storage layer");
                return customUuid.getBytes(StandardCharsets.UTF_8);
            }
        } catch (Throwable ignored) {
        }
        return input;
    }

    public static UUID interceptRandomUuid(UUID original) {
        if (!isTargetPackage()) {
            return original;
        }
        String customUuid = getCustomUuid();
        if (customUuid != null) {
            try {
                return UUID.fromString(customUuid);
            } catch (Throwable ignored) {
            }
        }
        return original;
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
                        if (isTargetPackage() && "getString".equals(name) && args != null && args.length >= 1 && args[0] instanceof String) {
                            String key = (String) args[0];
                            if (key.toLowerCase().contains("device_uuid")) {
                                Object origVal = method.invoke(base, args);
                                String customUuid = getCustomUuid();
                                // केवल तभी सादा UUID दें जब वैल्यू पहले से सादा UUID हो (ताकि Base64 ciphertext डिक्रिप्शन न टूटे)
                                if (customUuid != null && origVal instanceof String && UUID_V4_PATTERN.matcher((String) origVal).matches()) {
                                    Slog.d(TAG, "SharedPrefs.getString intercepted plain UUID key=" + key);
                                    return customUuid;
                                }
                                return origVal;
                            }
                        } else if (isTargetPackage() && "getAll".equals(name)) {
                            Object res = method.invoke(base, args);
                            if (res instanceof Map) {
                                String customUuid = getCustomUuid();
                                if (customUuid != null) {
                                    Map<String, Object> copy = new HashMap<>((Map<String, Object>) res);
                                    for (Map.Entry<String, Object> entry : copy.entrySet()) {
                                        String k = entry.getKey();
                                        Object v = entry.getValue();
                                        if (k != null && k.toLowerCase().contains("device_uuid") &&
                                            v instanceof String && UUID_V4_PATTERN.matcher((String) v).matches()) {
                                            Slog.d(TAG, "SharedPrefs.getAll intercepted plain UUID key=" + k);
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
            // Android 12 - 16 में static sSharedPrefsCache होता है
            Field staticCacheField = null;
            for (Field f : contextImplClass.getDeclaredFields()) {
                if (f.getName().contains("SharedPrefsCache")) {
                    staticCacheField = f;
                    break;
                }
            }
            if (staticCacheField != null) {
                staticCacheField.setAccessible(true);
                Object cacheObj = staticCacheField.get(java.lang.reflect.Modifier.isStatic(staticCacheField.getModifiers()) ? null : base);
                if (cacheObj instanceof Map) {
                    Map<Object, Object> outerMap = (Map<Object, Object>) cacheObj;
                    for (Map.Entry<Object, Object> entry : outerMap.entrySet()) {
                        if (entry.getValue() instanceof ArrayMap) {
                            ArrayMap<File, SharedPreferences> inner = (ArrayMap<File, SharedPreferences>) entry.getValue();
                            for (int i = 0; i < inner.size(); i++) {
                                SharedPreferences sp = inner.valueAt(i);
                                if (sp != null && !Proxy.isProxyClass(sp.getClass())) {
                                    inner.setValueAt(i, wrapSharedPreferences(sp));
                                }
                            }
                        }
                    }
                }
            }
        } catch (Throwable t) {
            Slog.d(TAG, "hookContextSharedPrefs note: " + t.getMessage());
        }
    }
}