package top.niunaijun.blackbox.utils;

import android.content.ContentResolver;
import android.content.Context;
import android.provider.Settings;
import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.util.HashMap;
import java.util.UUID;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedHelpers;
import top.niunaijun.blackbox.fake.frameworks.BLocationManager;

public class CustomUuidHook {
    private static final String TAG = "CustomUuidHook";
    private static final String UUID_FILE_NAME = "custom_device_uuid.txt";
    private static volatile boolean sInstalled = false;
    private static File sHostFilesDir = null;

    public static void install(Context context) {
        if (context != null) {
            sHostFilesDir = context.getFilesDir();
        }
        if (sInstalled) {
            return;
        }
        sInstalled = true;

        hookLocationSettings();
        hookUuidAndPayloads();
        Log.d(TAG, "CustomUuidHook installed successfully");
    }

    private static String getSavedCustomUuid() {
        try {
            File file = null;
            if (sHostFilesDir != null) {
                file = new File(sHostFilesDir, UUID_FILE_NAME);
            }
            if (file == null || !file.exists()) {
                File fallback = new File("/data/user/0/top.niunaijun.blackbox/files", UUID_FILE_NAME);
                if (fallback.exists()) {
                    file = fallback;
                }
            }
            if (file != null && file.exists() && file.canRead()) {
                try (BufferedReader br = new BufferedReader(new FileReader(file))) {
                    String line = br.readLine();
                    if (line != null) {
                        String trimmed = line.trim();
                        if (!trimmed.isEmpty()) {
                            return trimmed;
                        }
                    }
                }
            }
        } catch (Throwable ignored) {
        }
        return null;
    }

    private static boolean isTargetUuidKey(Object keyObj) {
        if (!(keyObj instanceof String)) {
            return false;
        }
        String k = ((String) keyObj).toLowerCase();
        return "device_uuid".equals(k) || "uuid".equals(k) || "deviceuuid".equals(k);
    }

    private static void hookLocationSettings() {
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
                            String name = (String) param.args[1];
                            if (BLocationManager.isFakeLocationEnable()) {
                                if (Settings.Secure.LOCATION_MODE.equals(name)) {
                                    param.setResult(Settings.Secure.LOCATION_MODE_HIGH_ACCURACY);
                                } else if (Settings.Secure.ALLOW_MOCK_LOCATION.equals(name)) {
                                    param.setResult(0);
                                }
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
                            String name = (String) param.args[1];
                            if (BLocationManager.isFakeLocationEnable()) {
                                if (Settings.Secure.LOCATION_MODE.equals(name)) {
                                    param.setResult(Settings.Secure.LOCATION_MODE_HIGH_ACCURACY);
                                } else if (Settings.Secure.ALLOW_MOCK_LOCATION.equals(name)) {
                                    param.setResult(0);
                                }
                            }
                        }
                    }
            );

            XposedHelpers.findAndHookMethod(
                    Settings.Secure.class,
                    "getString",
                    ContentResolver.class,
                    String.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            String name = (String) param.args[1];
                            if (BLocationManager.isFakeLocationEnable()) {
                                if (Settings.Secure.LOCATION_PROVIDERS_ALLOWED.equals(name)) {
                                    param.setResult("gps,network");
                                } else if (Settings.Secure.ALLOW_MOCK_LOCATION.equals(name)) {
                                    param.setResult("0");
                                }
                            }
                        }
                    }
            );
        } catch (Throwable t) {
            Log.w(TAG, "Failed to hook Settings.Secure: " + t.getMessage());
        }
    }

    private static void hookUuidAndPayloads() {
        try {
            XposedHelpers.findAndHookMethod(
                    UUID.class,
                    "randomUUID",
                    new XC_MethodHook() {
                        @Override
                        protected void afterHookedMethod(MethodHookParam param) {
                            String custom = getSavedCustomUuid();
                            if (custom != null) {
                                try {
                                    param.setResult(UUID.fromString(custom));
                                } catch (Throwable ignored) {
                                }
                            }
                        }
                    }
            );
        } catch (Throwable t) {
            Log.w(TAG, "Failed to hook UUID.randomUUID: " + t.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(
                    JSONObject.class,
                    "put",
                    String.class,
                    Object.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            if (isTargetUuidKey(param.args[0])) {
                                String custom = getSavedCustomUuid();
                                if (custom != null) {
                                    param.args[1] = custom;
                                }
                            }
                        }
                    }
            );
        } catch (Throwable t) {
            Log.w(TAG, "Failed to hook JSONObject.put: " + t.getMessage());
        }

        try {
            XposedHelpers.findAndHookMethod(
                    HashMap.class,
                    "put",
                    Object.class,
                    Object.class,
                    new XC_MethodHook() {
                        @Override
                        protected void beforeHookedMethod(MethodHookParam param) {
                            if (isTargetUuidKey(param.args[0])) {
                                String custom = getSavedCustomUuid();
                                if (custom != null) {
                                    param.args[1] = custom;
                                }
                            }
                        }
                    }
            );
        } catch (Throwable t) {
            Log.w(TAG, "Failed to hook HashMap.put: " + t.getMessage());
        }
    }
}
