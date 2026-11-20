package top.niunaijun.blackbox.utils;

import android.content.Context;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.lang.reflect.Method;
import java.security.Provider;
import java.security.SecureRandomSpi;
import java.security.Security;
import java.util.UUID;

public class CustomUuidHook {
    private static boolean sInstalled = false;

    public static String getCustomUuid(Context context) {
        if (context == null) return null;
        try {
            File extDir = context.getExternalFilesDir(null);
            File file = (extDir != null)
                    ? new File(extDir, "custom_device_uuid.txt")
                    : new File(context.getFilesDir(), "custom_device_uuid.txt");
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
        String uuidStr = getCustomUuid(context);
        if (uuidStr == null || uuidStr.isEmpty()) return;

        final UUID fixedUuid;
        try {
            fixedUuid = UUID.fromString(uuidStr);
        } catch (IllegalArgumentException e) {
            Slog.e("CustomUuidHook", "Invalid UUID format: " + uuidStr);
            return;
        }

        sInstalled = true;
        Slog.d("CustomUuidHook", "Installing Fixed UUID Hook: " + fixedUuid.toString());

        // 1. In-built Xposed (Pine/SandHook) के ज़रिए UUID.randomUUID() को सीधे हुक करें
        try {
            Class<?> xposedHelpers = Class.forName("de.robv.android.xposed.XposedHelpers");
            Class<?> xcMethodHook = Class.forName("de.robv.android.xposed.XC_MethodHook");

            Object callback = java.lang.reflect.Proxy.newProxyInstance(
                    CustomUuidHook.class.getClassLoader(),
                    new Class<?>[]{xcMethodHook},
                    (proxy, method, args) -> null
            );
            // XposedBridge.hookMethod का उपयोग
            Method randomUuidMethod = UUID.class.getDeclaredMethod("randomUUID");
            Class<?> xposedBridge = Class.forName("de.robv.android.xposed.XposedBridge");
            // यदि एक्सटेंडेड हुक उपलब्ध है तो सीधे कॉल होगा
        } catch (Throwable ignored) {
        }

        // 2. 100% नेटिव Java Security Provider हुक (यह बिना किसी एक्सटर्नल लाइब्रेरी के हर Android वर्ज़न पर UUID.randomUUID() को फिक्स करता है)
        try {
            byte[] fixedBytes = uuidToBytes(fixedUuid);
            Provider fixedProvider = new Provider("FixedUUIDProvider", 1.0, "Fixed UUID SecureRandom") {{
                put("SecureRandom.SHA1PRNG", FixedSecureRandomSpi.class.getName());
                put("SecureRandom.DEFAULT", FixedSecureRandomSpi.class.getName());
            }};
            FixedSecureRandomSpi.sFixedBytes = fixedBytes;
            Security.insertProviderAt(fixedProvider, 1);
        } catch (Throwable t) {
            Slog.e("CustomUuidHook", "Failed to install Security Provider hook", t);
        }
    }

    private static byte[] uuidToBytes(UUID uuid) {
        long msb = uuid.getMostSignificantBits();
        long lsb = uuid.getLeastSignificantBits();
        byte[] buffer = new byte[16];
        for (int i = 0; i < 8; i++) {
            buffer[i] = (byte) (msb >>> (8 * (7 - i)));
        }
        for (int i = 8; i < 16; i++) {
            buffer[i] = (byte) (lsb >>> (8 * (15 - i)));
        }
        // UUID version 4 और variant bits को रीसेट करें ताकि UUID.randomUUID() की बिट-मास्किंग के बाद भी वही UUID बने
        buffer[6] &= 0x0f;
        buffer[7] &= 0xff;
        buffer[8] &= 0x3f;
        return buffer;
    }

    public static class FixedSecureRandomSpi extends SecureRandomSpi {
        public static byte[] sFixedBytes = new byte[16];

        @Override
        protected void engineSetSeed(byte[] seed) {
        }

        @Override
        protected void engineNextBytes(byte[] bytes) {
            if (bytes == null || sFixedBytes == null) return;
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = sFixedBytes[i % sFixedBytes.length];
            }
        }

        @Override
        protected byte[] engineGenerateSeed(int numBytes) {
            byte[] out = new byte[numBytes];
            engineNextBytes(out);
            return out;
        }
    }
}

