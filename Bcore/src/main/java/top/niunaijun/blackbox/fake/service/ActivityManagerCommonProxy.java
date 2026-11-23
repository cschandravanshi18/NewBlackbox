package top.niunaijun.blackbox.fake.service;

import android.app.Activity;
import android.content.ClipData;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Method;

import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.app.BActivityThread;
import top.niunaijun.blackbox.fake.hook.MethodHook;
import top.niunaijun.blackbox.fake.hook.ProxyMethod;
import top.niunaijun.blackbox.fake.provider.FileProviderHandler;
import top.niunaijun.blackbox.utils.ComponentUtils;
import top.niunaijun.blackbox.utils.MethodParameterUtils;
import top.niunaijun.blackbox.utils.Slog;
import top.niunaijun.blackbox.utils.compat.BuildCompat;
import top.niunaijun.blackbox.utils.compat.StartActivityCompat;

import static android.content.pm.PackageManager.GET_META_DATA;

public class ActivityManagerCommonProxy {
    public static final String TAG = "CommonStub";

    private static File resolveVirtualShareFile(Uri uri) {
        if (uri == null || !"content".equalsIgnoreCase(uri.getScheme())) {
            return null;
        }
        String encodedPath = uri.getEncodedPath();
        if (encodedPath == null) {
            return null;
        }
        String cleanRel = encodedPath.startsWith("/") ? encodedPath.substring(1) : encodedPath;
        int slashIdx = cleanRel.indexOf('/');
        String subPath = (slashIdx >= 0) ? Uri.decode(cleanRel.substring(slashIdx + 1)) : Uri.decode(cleanRel);

        int userId = BActivityThread.getUserId();
        if (userId < 0) {
            userId = 0;
        }

        File[] candidates = new File[] {
            new File("/data/user/0/top.niunaijun.blackbox/blackbox/data/user/" + userId + "/com.vsk_teacher_attendance/" + subPath),
            new File("/data/user/0/top.niunaijun.blackbox/blackbox/data/user/0/com.vsk_teacher_attendance/" + subPath),
            new File("/data/data/com.vsk_teacher_attendance/" + subPath)
        };
        for (File f : candidates) {
            if (f != null && f.exists() && f.isFile() && f.canRead()) {
                return f;
            }
        }
        return null;
    }

    private static File copyToSharedTemp(File srcFile) {
        if (srcFile == null || !srcFile.exists()) {
            return null;
        }
        try {
            File outDir = new File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "BlackBoxShare");
            if (!outDir.exists() && !outDir.mkdirs()) {
                Context ctx = BActivityThread.getApplication();
                outDir = (ctx != null) ? ctx.getExternalCacheDir() : null;
            }
            if (outDir == null) {
                return null;
            }
            File dstFile = new File(outDir, srcFile.getName());
            try (InputStream in = new FileInputStream(srcFile);
                 OutputStream out = new FileOutputStream(dstFile)) {
                byte[] buf = new byte[4096];
                int len;
                while ((len = in.read(buf)) > 0) {
                    out.write(buf, 0, len);
                }
                out.flush();
            }
            return dstFile.exists() ? dstFile : null;
        } catch (Throwable t) {
            Slog.w(TAG, "copyToSharedTemp failed: " + t.getMessage());
            return null;
        }
    }

    private static Uri convertShareUri(Uri uri) {
        if (uri == null) {
            return null;
        }
        File virtualFile = resolveVirtualShareFile(uri);
        File copied = copyToSharedTemp(virtualFile);
        if (copied != null) {
            try {
                Uri converted = FileProviderHandler.convertFileUri(BActivityThread.getApplication(), Uri.fromFile(copied));
                if (converted != null) {
                    return converted;
                }
            } catch (Throwable ignored) {
            }
            return Uri.fromFile(copied);
        }
        try {
            Uri converted = FileProviderHandler.convertFileUri(BActivityThread.getApplication(), uri);
            if (converted != null) {
                return converted;
            }
        } catch (Throwable ignored) {
        }
        return uri;
    }

    private static void prepareSingleSendIntent(Intent sendIntent) {
        if (sendIntent == null) {
            return;
        }
        sendIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

        Uri streamUri = sendIntent.getParcelableExtra(Intent.EXTRA_STREAM);
        if (streamUri != null) {
            Uri newUri = convertShareUri(streamUri);
            if (newUri != null) {
                sendIntent.putExtra(Intent.EXTRA_STREAM, newUri);
                Context ctx = BActivityThread.getApplication();
                if (ctx != null) {
                    sendIntent.setClipData(ClipData.newUri(ctx.getContentResolver(), "share", newUri));
                }
            }
        }
    }

    private static void prepareShareIntent(Intent intent) {
        if (intent == null) {
            return;
        }
        if (Intent.ACTION_CHOOSER.equals(intent.getAction())) {
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            Intent target = intent.getParcelableExtra(Intent.EXTRA_INTENT);
            if (target != null) {
                prepareSingleSendIntent(target);
                if (target.getClipData() != null) {
                    intent.setClipData(target.getClipData());
                }
            }
            return;
        }
        String action = intent.getAction();
        if (Intent.ACTION_SEND.equals(action) || Intent.ACTION_SEND_MULTIPLE.equals(action)) {
            prepareSingleSendIntent(intent);
        }
    }

    @ProxyMethod("startActivity")
    public static class StartActivity extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            MethodParameterUtils.replaceFirstAppPkg(args);
            Intent intent = getIntent(args);
            Slog.d(TAG, "Hook in : " + intent);
            if (intent == null) {
                return method.invoke(who, args);
            }

            prepareShareIntent(intent);

            if ("android.content.pm.action.REQUEST_PERMISSIONS".equals(intent.getAction())) {
                final String[] permissions = intent.getStringArrayExtra("android.content.pm.extra.REQUEST_PERMISSIONS_NAMES");
                final int requestCode = StartActivityCompat.getRequestCode(args);
                final IBinder resultTo = StartActivityCompat.getResultTo(args);
                if (permissions != null) {
                    final int[] grantResults = new int[permissions.length];
                    for (int i = 0; i < permissions.length; i++) {
                        Array.setInt(grantResults, i, PackageManager.PERMISSION_GRANTED);
                    }
                    new Handler(Looper.getMainLooper()).post(() -> {
                        try {
                            Object mainThread = BlackBoxCore.mainThread();
                            Activity activity = null;
                            if (mainThread != null && resultTo != null) {
                                Method getAct = mainThread.getClass().getMethod("getActivity", IBinder.class);
                                activity = (Activity) getAct.invoke(mainThread, resultTo);
                            }
                            if (activity != null) {
                                try {
                                    java.lang.reflect.Field f = Activity.class.getDeclaredField("mHasCurrentPermissionsRequest");
                                    f.setAccessible(true);
                                    f.setBoolean(activity, false);
                                } catch (Throwable ignored) {
                                }

                                Intent resultIntent = new Intent("android.content.pm.action.REQUEST_PERMISSIONS");
                                resultIntent.putExtra("android.content.pm.extra.REQUEST_PERMISSIONS_NAMES", permissions);
                                resultIntent.putExtra("android.content.pm.extra.REQUEST_PERMISSIONS_RESULTS", grantResults);

                                boolean handledByActivityResult = false;
                                try {
                                    Method onActResult = findMethod(activity.getClass(), "onActivityResult", int.class, int.class, Intent.class);
                                    if (onActResult != null) {
                                        onActResult.setAccessible(true);
                                        onActResult.invoke(activity, requestCode, Activity.RESULT_OK, resultIntent);
                                        handledByActivityResult = true;
                                        Slog.d(TAG, "Dispatched GRANTED permissions via onActivityResult (requestCode=" + requestCode + ")");
                                    }
                                } catch (Throwable t) {
                                    Slog.w(TAG, "onActivityResult dispatch failed", t);
                                }

                                try {
                                    Method onReqPerm = findMethod(activity.getClass(), "onRequestPermissionsResult", int.class, String[].class, int[].class);
                                    if (onReqPerm != null) {
                                        onReqPerm.setAccessible(true);
                                        onReqPerm.invoke(activity, requestCode, permissions, grantResults);
                                        Slog.d(TAG, "Dispatched GRANTED permissions via onRequestPermissionsResult (requestCode=" + requestCode + ")");
                                    }
                                } catch (Throwable t) {
                                    if (!handledByActivityResult) {
                                        Slog.e(TAG, "onRequestPermissionsResult dispatch failed", t);
                                    }
                                }
                            }
                        } catch (Throwable t) {
                            Slog.e(TAG, "Auto-grant permission callback failed", t);
                        }
                    });
                    return 0;
                }
            }

            if (intent.getParcelableExtra("_B_|_target_") != null) {
                return method.invoke(who, args);
            }
            if (ComponentUtils.isRequestInstall(intent)) {
                File file = FileProviderHandler.convertFile(BActivityThread.getApplication(), intent.getData());

                if (file != null && file.exists()) {
                    try {
                        PackageInfo packageInfo = BlackBoxCore.getPackageManager().getPackageArchiveInfo(file.getAbsolutePath(), 0);
                        if (packageInfo != null) {
                            String packageName = packageInfo.packageName;
                            String hostPackageName = BlackBoxCore.getHostPkg();
                            if (packageName.equals(hostPackageName)) {
                                Slog.w(TAG, "Blocked attempt to install BlackBox app from within BlackBox: " + packageName);
                                return 0;
                            }
                        }
                    } catch (Exception e) {
                        Slog.w(TAG, "Could not verify if this is BlackBox app: " + e.getMessage());
                    }
                }

                if (BlackBoxCore.get().requestInstallPackage(file, BActivityThread.getUserId())) {
                    return 0;
                }
                intent.setData(FileProviderHandler.convertFileUri(BActivityThread.getApplication(), intent.getData()));
                return method.invoke(who, args);
            }
            String dataString = intent.getDataString();
            if (dataString != null && dataString.equals("package:" + BActivityThread.getAppPackageName())) {
                intent.setData(Uri.parse("package:" + BlackBoxCore.getHostPkg()));
            }

            ResolveInfo resolveInfo = BlackBoxCore.getBPackageManager().resolveActivity(
                    intent,
                    GET_META_DATA,
                    StartActivityCompat.getResolvedType(args),
                    BActivityThread.getUserId());
            if (resolveInfo == null) {
                String origPackage = intent.getPackage();
                if (intent.getPackage() == null && intent.getComponent() == null) {
                    intent.setPackage(BActivityThread.getAppPackageName());
                } else {
                    origPackage = intent.getPackage();
                }
                resolveInfo = BlackBoxCore.getBPackageManager().resolveActivity(
                        intent,
                        GET_META_DATA,
                        StartActivityCompat.getResolvedType(args),
                        BActivityThread.getUserId());
                if (resolveInfo == null) {
                    intent.setPackage(origPackage);
                    return method.invoke(who, args);
                }
            }

            intent.setExtrasClassLoader(who.getClass().getClassLoader());
            intent.setComponent(new ComponentName(resolveInfo.activityInfo.packageName, resolveInfo.activityInfo.name));
            BlackBoxCore.getBActivityManager().startActivityAms(BActivityThread.getUserId(),
                    StartActivityCompat.getIntent(args),
                    StartActivityCompat.getResolvedType(args),
                    StartActivityCompat.getResultTo(args),
                    StartActivityCompat.getResultWho(args),
                    StartActivityCompat.getRequestCode(args),
                    StartActivityCompat.getFlags(args),
                    StartActivityCompat.getOptions(args));
            return 0;
        }

        private static Method findMethod(Class<?> clazz, String name, Class<?>... paramTypes) {
            Class<?> current = clazz;
            while (current != null) {
                try {
                    return current.getDeclaredMethod(name, paramTypes);
                } catch (NoSuchMethodException ignored) {
                    current = current.getSuperclass();
                }
            }
            return null;
        }

        private Intent getIntent(Object[] args) {
            int index;
            if (BuildCompat.isR()) {
                index = 3;
            } else {
                index = 2;
            }
            if (args != null && index < args.length && Array.get(args, index) instanceof Intent) {
                return (Intent) Array.get(args, index);
            }
            if (args != null) {
                for (Object arg : args) {
                    if (arg instanceof Intent) {
                        return (Intent) arg;
                    }
                }
            }
            return null;
        }
    }

    @ProxyMethod("startActivities")
    public static class StartActivities extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            int index = getIntents();
            Intent[] intents = (Intent[]) Array.get(args, index++);
            String[] resolvedTypes = (String[]) Array.get(args, index++);
            IBinder resultTo = (IBinder) Array.get(args, index++);
            Bundle options = (Bundle) Array.get(args, index);

            if (!ComponentUtils.isSelf(intents)) {
                return method.invoke(who, args);
            }

            for (Intent intent : intents) {
                intent.setExtrasClassLoader(who.getClass().getClassLoader());
            }
            return BlackBoxCore.getBActivityManager().startActivities(BActivityThread.getUserId(),
                    intents, resolvedTypes, resultTo, options);
        }

        public int getIntents() {
            if (BuildCompat.isR()) {
                return 3;
            }
            return 2;
        }
    }

    @ProxyMethod("startIntentSenderForResult")
    public static class StartIntentSenderForResult extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("activityResumed")
    public static class ActivityResumed extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            BlackBoxCore.getBActivityManager().onActivityResumed((IBinder) Array.get(args, 0));
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("activityDestroyed")
    public static class ActivityDestroyed extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            BlackBoxCore.getBActivityManager().onActivityDestroyed((IBinder) Array.get(args, 0));
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("finishActivity")
    public static class FinishActivity extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            BlackBoxCore.getBActivityManager().onFinishActivity((IBinder) Array.get(args, 0));
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("getAppTasks")
    public static class GetAppTasks extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            MethodParameterUtils.replaceFirstAppPkg(args);
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("getCallingPackage")
    public static class getCallingPackage extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            return BlackBoxCore.getBActivityManager().getCallingPackage((IBinder) Array.get(args, 0), BActivityThread.getUserId());
        }
    }

    @ProxyMethod("getCallingActivity")
    public static class getCallingActivity extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            return BlackBoxCore.getBActivityManager().getCallingActivity((IBinder) Array.get(args, 0), BActivityThread.getUserId());
        }
    }
}