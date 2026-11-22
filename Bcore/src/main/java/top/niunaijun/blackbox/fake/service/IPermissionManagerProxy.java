package top.niunaijun.blackbox.fake.service;

import android.content.pm.PackageManager;
import android.util.Log;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.util.Locale;

import black.android.app.BRActivityThread;
import black.android.os.BRServiceManager;
import black.android.permission.BRIPermissionManagerStub;
import top.niunaijun.blackbox.fake.hook.BinderInvocationStub;
import top.niunaijun.blackbox.fake.hook.MethodHook;
import top.niunaijun.blackbox.fake.service.base.ValueMethodProxy;
import top.niunaijun.blackbox.utils.MethodParameterUtils;
import top.niunaijun.blackbox.utils.compat.BuildCompat;

public class IPermissionManagerProxy extends BinderInvocationStub {
    public static final String TAG = "IPermissionManagerProxy";
    private static final String P = "permissionmgr";

    public IPermissionManagerProxy() {
        super(BRServiceManager.get().getService(P));
    }

    @Override
    protected Object getWho() {
        return BRIPermissionManagerStub.get().asInterface(BRServiceManager.get().getService(P));
    }

    @Override
    protected void inject(Object baseInvocation, Object proxyInvocation) {
        replaceSystemService(P);
        try {
            BRActivityThread.getWithException()._set_sPermissionManager(proxyInvocation);
        } catch (Throwable ignored) {
        }
    }

    private static boolean isLocationPermission(String perm) {
        if (perm == null) return false;
        String upper = perm.toUpperCase(Locale.ROOT);
        return upper.contains("LOCATION") || upper.contains("ACCESS_COARSE") || upper.contains("ACCESS_FINE");
    }

    private static boolean hasLocationPermissionArg(Object[] args) {
        if (args == null) return false;
        for (Object arg : args) {
            if (arg instanceof String && isLocationPermission((String) arg)) {
                return true;
            }
            if (arg instanceof String[]) {
                for (String s : (String[]) arg) {
                    if (isLocationPermission(s)) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private Object handleLocationPermission(Object who, Method method, Object... args) throws Throwable {
        MethodParameterUtils.replaceFirstAppPkg(args);
        if (hasLocationPermissionArg(args)) {
            Log.d(TAG, "Granting location permission in " + method.getName());
            return PackageManager.PERMISSION_GRANTED;
        }
        try {
            return method.invoke(who, args);
        } catch (SecurityException e) {
            Log.w(TAG, "SecurityException in " + method.getName() + ", returning PERMISSION_DENIED safely", e);
            return PackageManager.PERMISSION_DENIED;
        }
    }

    @Override
    protected void onBindMethod() {
        super.onBindMethod();
        addMethodHook(new ValueMethodProxy("addPermissionAsync", true));
        addMethodHook(new ValueMethodProxy("addPermission", true));
        addMethodHook(new ValueMethodProxy("performDexOpt", true));
        addMethodHook(new ValueMethodProxy("performDexOptIfNeeded", false));
        addMethodHook(new ValueMethodProxy("performDexOptSecondary", true));
        addMethodHook(new ValueMethodProxy("addOnPermissionsChangeListener", 0));
        addMethodHook(new ValueMethodProxy("removeOnPermissionsChangeListener", 0));
        addMethodHook(new ValueMethodProxy("checkDeviceIdentifierAccess", false));
        addMethodHook(new ValueMethodProxy("shouldShowRequestPermissionRationale", false));

        addMethodHook(new MethodHook() {
            @Override
            protected String getMethodName() {
                return "checkPermission";
            }

            @Override
            protected Object hook(Object who, Method method, Object... args) throws Throwable {
                return handleLocationPermission(who, method, args);
            }
        });

        addMethodHook(new MethodHook() {
            @Override
            protected String getMethodName() {
                return "checkUidPermission";
            }

            @Override
            protected Object hook(Object who, Method method, Object... args) throws Throwable {
                return handleLocationPermission(who, method, args);
            }
        });

        if (BuildCompat.isOreo()) {
            addMethodHook(new ValueMethodProxy("notifyDexLoad", 0));
            addMethodHook(new ValueMethodProxy("notifyPackageUse", 0));
            addMethodHook(new ValueMethodProxy("setInstantAppCookie", false));
            addMethodHook(new ValueMethodProxy("isInstantApp", false));
        }
    }

    @Override
    public boolean isBadEnv() {
        return false;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object... args) throws Throwable {
        MethodParameterUtils.replaceFirstAppPkg(args);
        String mName = method.getName();
        if (mName != null && mName.startsWith("check") && mName.contains("Permission") && hasLocationPermissionArg(args)) {
            Log.d(TAG, "Granting location permission via invoke for " + mName);
            return PackageManager.PERMISSION_GRANTED;
        }
        try {
            return super.invoke(proxy, method, args);
        } catch (Throwable t) {
            if (hasLocationPermissionArg(args)) {
                return PackageManager.PERMISSION_GRANTED;
            }
            throw t;
        }
    }
}
