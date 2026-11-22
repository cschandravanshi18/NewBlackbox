package top.niunaijun.blackbox.utils;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;

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

        String customUuid = getSavedCustomUuid();
        if (customUuid != null) {
            Log.d(TAG, "CustomUuidHook loaded custom UUID length=" + customUuid.length());
        } else {
            Log.d(TAG, "CustomUuidHook initialized (no custom UUID file found)");
        }
    }

    public static String getSavedCustomUuid() {
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
}
