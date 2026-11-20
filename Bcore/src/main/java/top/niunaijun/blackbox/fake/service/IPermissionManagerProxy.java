package top.niunaijun.blackbox.fake.service;

import android.content.pm.PackageManager;
import java.lang.reflect.Array;
import java.lang.reflect.Method;

import black.android.app.BRActivityThread;
import black.android.os.BRServiceManager;
import black.android.permission.BRIPermissionManagerStub;
import top.niunaijun.blackbox.fake.hook.BinderInvocationStub;
import top.niunaijun.blackbox.fake.hook.MethodHook;
import top.niunaijun.blackbox.fake.service.base.ValueMethodProxy;
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
        replaceSystemService("permissionmgr");
        BRActivityThread.getWithException()._set_sPermissionManager(proxyInvocation);
    }

    private Object handleLocationPermission(Object who, Method method, Object[] args) throws Throwable {
        if (args != null) {
            for (int i = 0; i < args.length; i++) {
                Object arg = Array.get(args, i);
                if (arg instanceof String) {
                    String perm = (String) arg;
                    if (perm.contains("LOCATION")) {
                        return PackageManager.PERMISSION_GRANTED;
                    }
                }
            }
        }
        return method.invoke(who, args);
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
}
