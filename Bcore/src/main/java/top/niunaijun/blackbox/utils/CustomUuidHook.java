package top.niunaijun.blackbox.utils;

import android.content.Context;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.UUID;

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

    public static void install(Context context) {
        if (sInstalled) return;
        sInstalled = true;

        String uuidStr = readUuidFromDisk(context);
        if (uuidStr == null || uuidStr.isEmpty()) return;

        try {
            sFixedUuid = UUID.fromString(uuidStr);
            sFixedUuidStr = uuidStr;
            Slog.d("CustomUuidHook", "Loaded Fixed UUID: " + sFixedUuidStr);
        } catch (IllegalArgumentException e) {
            Slog.e("CustomUuidHook", "Invalid UUID format: " + uuidStr);
            return;
        }

        // Java UUID.Holder.numberGenerator को फिक्स सीड वाले SecureRandom से बदलें
        // ताकि बिना किसी एक्सटर्नल लाइब्रेरी के UUID.randomUUID() हमेशा वही UUID बनाए!
        try {
            Class<?> holderClass = Class.forName("java.util.UUID$Holder");
            Field generatorField = holderClass.getDeclaredField("numberGenerator");
            generatorField.setAccessible(true);

            // Unsafe या Reflection से static final फ़ील्ड अपडेट करें
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
                Slog.d("CustomUuidHook", "Successfully replaced UUID numberGenerator via Unsafe!");
            } catch (Throwable unsafeErr) {
                generatorField.set(null, fixedRandom);
            }
        } catch (Throwable t) {
            Slog.e("CustomUuidHook", "Failed to replace UUID numberGenerator", t);
        }
    }
}
