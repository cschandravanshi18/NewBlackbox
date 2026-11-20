package top.niunaijun.blackbox.utils;

import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings;
import org.json.JSONObject;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.UUID;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import top.niunaijun.blackbox.fake.frameworks.BLocationManager;

public class CustomUuidHook {
    private static boolean sInstalled = false;

    public static String getCustomUuid(Context context) {
        if (context == null) return null;
        try {
            File file = new File(context.getFilesDir(), "custom_device_uuid.txt");
            if (!file.exists()) {
                File extDir = context.getExternalFilesDir(null);
                if (extDir != null) {
                    file = new File(extDir, "custom_device_uuid.txt");
                }
            }
            if (!file.exists()) return null;

            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line = reader.readLine();
            reader.close();
            if (line != null && !line.trim().isEmpty()) {
                return line.trim();
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    public static void install(Context context) {
        if (sInstalled) return;
        sInstalled = true;

        try {
            XposedHelpers.findAndHookMethod(
                    Settings.Secure.class,
                    "getInt",
                    ContentResolver.class,
                    String.class,
                    int.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String name = (String) Array.get(param.args, 1);
                            if (Settings.Secure.LOCATION_MODE.equals(name) && BLocationManager.isFakeLocationEnable()) {
                                param.setResult(Settings.Secure.LOCATION_MODE_HIGH_ACCURACY);
                            }
                        }
                    }
            );
            XposedHelpers.findAndHookMethod(
                    Settings.Secure.class,
                    "getInt",
                    ContentResolver.class,
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String name = (String) Array.get(param.args, 1);
                            if (Settings.Secure.LOCATION_MODE.equals(name) && BLocationManager.isFakeLocationEnable()) {
                                param.setResult(Settings.Secure.LOCATION_MODE_HIGH_ACCURACY);
                            }
                        }
                    }
            );
        } catch (Throwable t) {
            Slog.e("CustomUuidHook", "Failed to hook Settings.Secure.LOCATION_MODE", t);
        }
                final String uuidStr = getCustomUuid(context);
        if (uuidStr == null || uuidStr.isEmpty()) return;

        final UUID fixedUuid;
        try {
            fixedUuid = UUID.fromString(uuidStr);
        } catch (IllegalArgumentException e) {
            Slog.e("CustomUuidHook", "Invalid UUID format: " + uuidStr);
            return;
        }

        Slog.d("CustomUuidHook", "Installing Universal UUID Hook: " + uuidStr);

        try {
            Method randomUuidMethod = UUID.class.getDeclaredMethod("randomUUID");
            XposedBridge.hookMethod(randomUuidMethod, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    param.setResult(fixedUuid);
                }
            });
        } catch (Throwable t) {
            Slog.e("CustomUuidHook", "UUID.randomUUID hook failed", t);
        }

        try {
            Method putMethod = JSONObject.class.getDeclaredMethod("put", String.class, Object.class);
            XposedBridge.hookMethod(putMethod, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.args != null && param.args.length >= 2) {
                        Object firstArg = Array.get(param.args, 0);
                        if (firstArg instanceof String && isUuidKey((String) firstArg)) {
                            Array.set(param.args, 1, uuidStr);
                        }
                    }
                }
            });
        } catch (Throwable ignored) {
        }

        try {
            XposedHelpers.findAndHookMethod(HashMap.class, "put", Object.class, Object.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) {
                    if (param.args != null && param.args.length >= 2) {
                        Object firstArg = Array.get(param.args, 0);
                        if (firstArg instanceof String && isUuidKey((String) firstArg)) {
                            Array.set(param.args, 1, uuidStr);
                        }
                    }
                }
            });
        } catch (Throwable ignored) {
        }
    }

    private static boolean isUuidKey(String key) {
        if (key == null) return false;
        String lower = key.toLowerCase();
        return lower.equals("device_uuid") || lower.equals("deviceuuid") || lower.equals("uuid");
    }
}
