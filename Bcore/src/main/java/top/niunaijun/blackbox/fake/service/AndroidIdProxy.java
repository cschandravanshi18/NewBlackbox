package top.niunaijun.blackbox.fake.service;

import java.lang.reflect.Method;

import top.niunaijun.blackbox.fake.hook.ClassInvocationStub;
import top.niunaijun.blackbox.fake.hook.MethodHook;
import top.niunaijun.blackbox.fake.hook.ProxyMethod;
import top.niunaijun.blackbox.utils.CustomUuidHook;
import top.niunaijun.blackbox.utils.Slog;

public class AndroidIdProxy extends ClassInvocationStub {
    public static final String TAG = "AndroidIdProxy";

    public AndroidIdProxy() {
        super();
    }

    @Override
    protected Object getWho() {
        return null;
    }

    @Override
    protected void inject(Object baseInvocation, Object proxyInvocation) {
    }

    @Override
    public boolean isBadEnv() {
        return false;
    }

    private static String getEffectiveAndroidId() {
        String customUuid = CustomUuidHook.getSavedCustomUuid();
        if (customUuid != null && !customUuid.isEmpty()) {
            String hexOnly = customUuid.replace("-", "").trim();
            if (hexOnly.length() >= 16) {
                return hexOnly.substring(0, 16).toLowerCase();
            }
            return customUuid;
        }
        return generateMockAndroidId();
    }

    private static boolean isIdKey(String key) {
        if (key == null) return false;
        String lower = key.toLowerCase();
        return lower.contains("android_id") ||
                lower.contains("secure_id") ||
                lower.contains("device_id") ||
                lower.contains("uuid");
    }

    @ProxyMethod("getAndroidId")
    public static class GetAndroidId extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            try {
                Slog.d(TAG, "AndroidId: Handling getAndroidId call");
                String customUuid = CustomUuidHook.getSavedCustomUuid();
                if (customUuid != null && !customUuid.isEmpty()) {
                    return getEffectiveAndroidId();
                }
                Object result = (who != null) ? method.invoke(who, args) : null;
                if (result == null || "0".equals(result.toString()) || "".equals(result.toString())) {
                    return generateMockAndroidId();
                }
                return result;
            } catch (Exception e) {
                Slog.w(TAG, "AndroidId: GetAndroidId error, returning effective ID", e);
                return getEffectiveAndroidId();
            }
        }
    }

    @ProxyMethod("getString")
    public static class GetString extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            try {
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (isIdKey(key)) {
                        String customUuid = CustomUuidHook.getSavedCustomUuid();
                        if (customUuid != null && !customUuid.isEmpty()) {
                            return getEffectiveAndroidId();
                        }
                    }
                }
                Object result = (who != null) ? method.invoke(who, args) : null;
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (isIdKey(key) && (result == null || "0".equals(result.toString()) || "".equals(result.toString()))) {
                        return generateMockAndroidId();
                    }
                }
                return result;
            } catch (Exception e) {
                Slog.w(TAG, "AndroidId: GetString error", e);
                return (who != null) ? method.invoke(who, args) : getEffectiveAndroidId();
            }
        }
    }

    @ProxyMethod("getLong")
    public static class GetLong extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            try {
                Object result = (who != null) ? method.invoke(who, args) : null;
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (isIdKey(key) && (result == null || ((Number) result).longValue() == 0)) {
                        return generateMockAndroidIdLong();
                    }
                }
                return result;
            } catch (Exception e) {
                Slog.w(TAG, "AndroidId: GetLong error", e);
                return generateMockAndroidIdLong();
            }
        }
    }

    @ProxyMethod("get")
    public static class Get extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            try {
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (isIdKey(key)) {
                        String customUuid = CustomUuidHook.getSavedCustomUuid();
                        if (customUuid != null && !customUuid.isEmpty()) {
                            return getEffectiveAndroidId();
                        }
                    }
                }
                Object result = (who != null) ? method.invoke(who, args) : null;
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (isIdKey(key) && (result == null || "0".equals(result.toString()) || "".equals(result.toString()))) {
                        return generateMockAndroidId();
                    }
                }
                return result;
            } catch (Exception e) {
                Slog.w(TAG, "AndroidId: Get error", e);
                return (who != null) ? method.invoke(who, args) : getEffectiveAndroidId();
            }
        }
    }

    @ProxyMethod("read")
    public static class Read extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            try {
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (isIdKey(key)) {
                        String customUuid = CustomUuidHook.getSavedCustomUuid();
                        if (customUuid != null && !customUuid.isEmpty()) {
                            return getEffectiveAndroidId();
                        }
                    }
                }
                Object result = (who != null) ? method.invoke(who, args) : null;
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (isIdKey(key) && (result == null || "0".equals(result.toString()) || "".equals(result.toString()))) {
                        return generateMockAndroidId();
                    }
                }
                return result;
            } catch (Exception e) {
                Slog.w(TAG, "AndroidId: Read error", e);
                return (who != null) ? method.invoke(who, args) : getEffectiveAndroidId();
            }
        }
    }

    private static String generateMockAndroidId() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(Integer.toHexString((int) (Math.random() * 16)));
        }
        String mockId = sb.toString().toLowerCase();
        Slog.d(TAG, "AndroidId: Generated mock Android ID: " + mockId);
        return mockId;
    }

    private static Long generateMockAndroidIdLong() {
        long mockId = (long) (Math.random() * Long.MAX_VALUE);
        Slog.d(TAG, "AndroidId: Generated mock Android ID long: " + mockId);
        return mockId;
    }
}
