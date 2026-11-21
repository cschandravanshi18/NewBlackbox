package top.niunaijun.blackbox.utils;

import android.content.Context;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import top.niunaijun.blackbox.app.BActivityThread;

public class CustomUuidHook {
    private static boolean sInstalled = false;
    private static String sFixedUuidStr = null;
    private static UUID sFixedUuid = null;

    public static String getFixedUuidString() {
        return sFixedUuidStr;
    }

    public static UUID getFixedUuid() {
        return sFixedUuid;
    }

    public static String readUuidFromDisk(Context context) {
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

    public static void install(final Context context) {
        if (sInstalled) return;
        sInstalled = true;

        final String uuidStr = readUuidFromDisk(context);
        if (uuidStr == null || uuidStr.isEmpty()) return;

        try {
            sFixedUuid = UUID.fromString(uuidStr);
            sFixedUuidStr = uuidStr;
            Slog.d("CustomUuidHook", "Loaded Fixed UUID: " + sFixedUuidStr);
        } catch (IllegalArgumentException e) {
            Slog.e("CustomUuidHook", "Invalid UUID format: " + uuidStr);
            return;
        }

        try {
            Class<?> holderClass = Class.forName("java.util.UUID$Holder");
            Field generatorField = holderClass.getDeclaredField("numberGenerator");
            generatorField.setAccessible(true);

            java.security.SecureRandom fixedRandom = new java.security.SecureRandom() {
                @Override
                public synchronized void nextBytes(byte... bytes) {
                    if (bytes == null || bytes.length < 16 || sFixedUuid == null) return;
                    long msb = sFixedUuid.getMostSignificantBits();
                    long lsb = sFixedUuid.getLeastSignificantBits();
                    for (int i = 0; i < 8; i++) {
                        java.lang.reflect.Array.setByte(bytes, i, (byte) (msb >>> (8 * (7 - i))));
                    }
                    for (int i = 8; i < 16; i++) {
                        java.lang.reflect.Array.setByte(bytes, i, (byte) (lsb >>> (8 * (15 - i))));
                    }
                }
            };

            try {
                Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
                Field theUnsafe = unsafeClass.getDeclaredField("theUnsafe");
                theUnsafe.setAccessible(true);
                Object unsafe = theUnsafe.get(null);

                Method staticFieldBase = unsafeClass.getMethod("staticFieldBase", Field.class);
                Method staticFieldOffset = unsafeClass.getMethod("staticFieldOffset", Field.class);
                Method putObject = unsafeClass.getMethod("putObject", Object.class, long.class, Object.class);

                Object base = staticFieldBase.invoke(unsafe, generatorField);
                long offset = (Long) staticFieldOffset.invoke(unsafe, generatorField);
                putObject.invoke(unsafe, base, offset, fixedRandom);
            } catch (Throwable unsafeErr) {
                generatorField.set(null, fixedRandom);
            }
        } catch (Throwable t) {
            Slog.e("CustomUuidHook", "Failed to replace UUID numberGenerator", t);
        }

        patchFlutterSharedPrefs(context, uuidStr);
    }

    private static void patchFlutterSharedPrefs(Context context, String fixedUuid) {
        try {
            String pkg = BActivityThread.getAppPackageName();
            int userId = BActivityThread.getUserId();
            if (pkg != null && !pkg.isEmpty()) {
                File appDir = new File(context.getDataDir(), "blackbox/data/user/" + userId + "/" + pkg);
                applyPrefsPatch(appDir, fixedUuid);
            }

            File dataRoot = new File(context.getDataDir(), "blackbox/data/user/" + userId);
            if (dataRoot.exists()) {
                var appDirs = dataRoot.listFiles();
                if (appDirs != null) {
                    for (File dir : appDirs) {
                        applyPrefsPatch(dir, fixedUuid);
                    }
                }
            }
        } catch (Throwable ignored) {
        }
    }

    private static void applyPrefsPatch(File appDir, String fixedUuid) {
        try {
            File prefsDir = new File(appDir, "shared_prefs");
            if (!prefsDir.exists()) {
                prefsDir.mkdirs();
            }

            // FlutterSharedPreferences.xml में सभी संभावित नामों से फिक्स UUID लिखें
            File flutterPrefs = new File(prefsDir, "FlutterSharedPreferences.xml");
            if (flutterPrefs.exists()) {
                flutterPrefs.setWritable(true);
            }
            String initialXml = "<?xml version='1.0' encoding='utf-8' standalone='yes' ?>\n" +
                    "<map>\n" +
                    "    <string name=\"flutter.device_uuid\">" + fixedUuid + "</string>\n" +
                    "    <string name=\"device_uuid\">" + fixedUuid + "</string>\n" +
                    "</map>\n";
            FileOutputStream fos = new FileOutputStream(flutterPrefs);
            fos.write(initialXml.getBytes(StandardCharsets.UTF_8));
            fos.close();
            flutterPrefs.setReadOnly();
            Slog.d("CustomUuidHook", "Locked FlutterSharedPreferences.xml with fixed UUID for " + appDir.getName());
        } catch (Throwable ignored) {
        }
    }
}
