package top.niunaijun.blackbox.fake.service;

import android.app.Activity;
import android.content.ComponentName;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.IBinder;
import android.os.Looper;

import java.io.File;
import java.lang.reflect.Array;
import java.lang.reflect.Method;

import black.android.app.BRActivityThread;
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

    @ProxyMethod("startActivity")
    public static class StartActivity extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            MethodParameterUtils.replaceFirstAppPkg(args);
            Intent intent = getIntent(args);
            Slog.d(TAG, "Hook in : " + intent);
            assert intent != null;

                if ("android.content.pm.action.REQUEST_PERMISSIONS".equals(intent.getAction())) {
                final var permissions = intent.getStringArrayExtra("android.content.pm.extra.REQUEST_PERMISSIONS_NAMES");
                final int requestCode = StartActivityCompat.getRequestCode(args);
                final IBinder resultTo = StartActivityCompat.getResultTo(args);
                if (permissions != null) {
                    final var grantResults = new int[permissions.length];
                    for (int i = 0; i < permissions.length; i++) {
                        Array.setInt(grantResults, i, PackageManager.PERMISSION_GRANTED);
                    }
                    new Handler(Looper.getMainLooper()).post(() -> {
                        try {
                            Object mainThread = BlackBoxCore.mainThread();
                            Method getAct = mainThread.getClass().getMethod("getActivity", IBinder.class);
                            Activity activity = (Activity) getAct.invoke(mainThread, resultTo);
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
                                try {
                                    Method dispatch = Activity.class.getDeclaredMethod("dispatchRequestPermissionsResult", int.class, Intent.class);
                                    dispatch.setAccessible(true);
                                    dispatch.invoke(activity, requestCode, resultIntent);
                                } catch (Throwable e) {
                                    Method m = Activity.class.getDeclaredMethod("onRequestPermissionsResult", int.class, String[].class, int[].class);
                                    m.setAccessible(true);
                                    m.invoke(activity, requestCode, permissions, grantResults);
                                }
                                Slog.d(TAG, "Dispatched GRANTED permissions result to Activity!");
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

        private Intent getIntent(Object[] args) {
            int index;
            if (BuildCompat.isR()) {
                index = 3;
            } else {
                index = 2;
            }
            if (Array.get(args, index) instanceof Intent) {
                return (Intent) Array.get(args, index);
            }
            for (Object arg : args) {
                if (arg instanceof Intent) {
                    return (Intent) arg;
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
            var intents = (Intent[]) Array.get(args, index++);
            var resolvedTypes = (String[]) Array.get(args, index++);
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
