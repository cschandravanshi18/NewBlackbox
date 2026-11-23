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

    private static String getCustomOrFallbackId(Object currentResult) {
        String customUuid = CustomUuidHook.getSavedCustomUuid();
        if (customUuid != null && !customUuid.isEmpty()) {
            Slog.d(TAG, "AndroidId: Returning saved custom UUID: " + customUuid);
            return customUuid;
        }
        if (currentResult != null && !"0".equals(currentResult.toString()) && !"".equals(currentResult.toString())) {
            return currentResult.toString();
        }
        return generateMockAndroidId();
    }

    @ProxyMethod("getAndroidId")
    public static class GetAndroidId extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            try {
                String customUuid = CustomUuidHook.getSavedCustomUuid();
                if (customUuid != null && !customUuid.isEmpty()) {
                    return customUuid;
                }
                Object result = method.invoke(who, args);
                return getCustomOrFallbackId(result);
            } catch (Exception e) {
                return getCustomOrFallbackId(null);
            }
        }
    }

    @ProxyMethod("getString")
    public static class GetString extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            if (args != null && args.length > 0 && args[0] instanceof String) {
                String key = (String) args[0];
                if (key.contains("android_id") || key.contains("ANDROID_ID") ||
                        key.contains("secure_id") || key.contains("device_id")) {
                    String customUuid = CustomUuidHook.getSavedCustomUuid();
                    if (customUuid != null && !customUuid.isEmpty()) {
                        return customUuid;
                    }
                }
            }
            try {
                Object result = method.invoke(who, args);
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (key.contains("android_id") || key.contains("ANDROID_ID") ||
                            key.contains("secure_id") || key.contains("device_id")) {
                        return getCustomOrFallbackId(result);
                    }
                }
                return result;
            } catch (Exception e) {
                return method.invoke(who, args);
            }
        }
    }

    @ProxyMethod("getLong")
    public static class GetLong extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            try {
                Object result = method.invoke(who, args);
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (key.contains("android_id") || key.contains("ANDROID_ID") ||
                            key.contains("secure_id") || key.contains("device_id")) {
                        if (result == null || ((Number) result).longValue() == 0) {
                            return generateMockAndroidIdLong();
                        }
                    }
                }
                return result;
            } catch (Exception e) {
                return method.invoke(who, args);
            }
        }
    }

    @ProxyMethod("get")
    public static class Get extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            if (args != null && args.length > 0 && args[0] instanceof String) {
                String key = (String) args[0];
                if (key.contains("android_id") || key.contains("ANDROID_ID") ||
                        key.contains("secure_id") || key.contains("device_id")) {
                    String customUuid = CustomUuidHook.getSavedCustomUuid();
                    if (customUuid != null && !customUuid.isEmpty()) {
                        return customUuid;
                    }
                }
            }
            try {
                Object result = method.invoke(who, args);
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (key.contains("android_id") || key.contains("ANDROID_ID") ||
                            key.contains("secure_id") || key.contains("device_id")) {
                        return getCustomOrFallbackId(result);
                    }
                }
                return result;
            } catch (Exception e) {
                return method.invoke(who, args);
            }
        }
    }

    @ProxyMethod("read")
    public static class Read extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object[] args) throws Throwable {
            if (args != null && args.length > 0 && args[0] instanceof String) {
                String key = (String) args[0];
                if (key.contains("android_id") || key.contains("ANDROID_ID") ||
                        key.contains("secure_id") || key.contains("device_id")) {
                    String customUuid = CustomUuidHook.getSavedCustomUuid();
                    if (customUuid != null && !customUuid.isEmpty()) {
                        return customUuid;
                    }
                }
            }
            try {
                Object result = method.invoke(who, args);
                if (args != null && args.length > 0 && args[0] instanceof String) {
                    String key = (String) args[0];
                    if (key.contains("android_id") || key.contains("ANDROID_ID") ||
                            key.contains("secure_id") || key.contains("device_id")) {
                        return getCustomOrFallbackId(result);
                    }
                }
                return result;
            } catch (Exception e) {
                return method.invoke(who, args);
            }
        }
    }

    private static String generateMockAndroidId() {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            sb.append(Integer.toHexString((int) (Math.random() * 16)));
        }
        return sb.toString().toUpperCase();
    }

    private static Long generateMockAndroidIdLong() {
        return (long) (Math.random() * Long.MAX_VALUE);
    }
}
