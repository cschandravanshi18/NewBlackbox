package top.niunaijun.blackbox.fake.service;

import android.content.Context;
import android.location.Location;
import android.location.LocationManager;
import android.os.Build;
import android.os.IBinder;
import android.os.IInterface;
import android.os.SystemClock;
import android.util.Log;

import java.lang.reflect.Array;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Random;

import black.android.location.BRILocationListener;
import black.android.location.BRILocationManagerStub;
import black.android.location.provider.BRProviderProperties;
import black.android.os.BRServiceManager;
import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.app.BActivityThread;
import top.niunaijun.blackbox.entity.location.BLocation;
import top.niunaijun.blackbox.fake.frameworks.BLocationManager;
import top.niunaijun.blackbox.fake.hook.BinderInvocationStub;
import top.niunaijun.blackbox.fake.hook.MethodHook;
import top.niunaijun.blackbox.fake.hook.ProxyMethod;
import top.niunaijun.blackbox.utils.MethodParameterUtils;

public class ILocationManagerProxy extends BinderInvocationStub {
    public static final String TAG = "ILocationManagerProxy";
    private static final Random sRandom = new Random();

    public ILocationManagerProxy() {
        super(BRServiceManager.get().getService(Context.LOCATION_SERVICE));
    }

    @Override
    protected Object getWho() {
        return BRILocationManagerStub.get().asInterface(BRServiceManager.get().getService(Context.LOCATION_SERVICE));
    }

    @Override
    protected void inject(Object baseInvocation, Object proxyInvocation) {
        replaceSystemService(Context.LOCATION_SERVICE);
    }

    @Override
    public boolean isBadEnv() {
        try {
            Map<String, IBinder> cache = BRServiceManager.get().sCache();
            if (cache != null) {
                IBinder current = cache.get(Context.LOCATION_SERVICE);
                return current != this;
            }
        } catch (Throwable ignored) {
        }
        return false;
    }

    private static String resolvePackageName() {
        String pkg = BActivityThread.getAppPackageName();
        if (pkg == null || pkg.isEmpty()) {
            pkg = BlackBoxCore.get().getCurrentAppPackage();
        }
        return pkg;
    }

    private static int resolveUserId() {
        int userId = BActivityThread.getUserId();
        return userId >= 0 ? userId : 0;
    }

    private static BLocation resolveBLocation() {
        int userId = resolveUserId();
        String pkg = resolvePackageName();
        BLocation bLoc = null;
        if (pkg != null) {
            bLoc = BLocationManager.get().getLocation(userId, pkg);
        }
        if (bLoc == null) {
            bLoc = BLocationManager.get().getGlobalLocation();
        }
        return bLoc;
    }

    private static boolean shouldSpoofLocation() {
        String pkg = resolvePackageName();
        if (pkg == null || "top.niunaijun.blackbox".equals(pkg)) {
            return false;
        }
        if (BLocationManager.isFakeLocationEnable()) {
            return true;
        }
        return resolveBLocation() != null;
    }

    private static void clearMockFlags(Location loc) {
        if (loc == null) return;
        try {
            Method m = Location.class.getMethod("setIsFromMockProvider", boolean.class);
            m.invoke(loc, false);
        } catch (Throwable ignored) {
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            try {
                Method m = Location.class.getMethod("setMock", boolean.class);
                m.invoke(loc, false);
            } catch (Throwable ignored) {
            }
        }
    }

    private static Object createDummyCancellationSignal() {
        try {
            Class<?> csClass = Class.forName("android.os.CancellationSignal");
            Method createTransport = csClass.getMethod("createTransport");
            return createTransport.invoke(null);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean invokeLocationOnTarget(Object target, Location loc) {
        if (target == null || loc == null) return false;

        for (Method m : target.getClass().getMethods()) {
            if ("onLocationChanged".equals(m.getName())) {
                Class<?>[] params = m.getParameterTypes();
                try {
                    if (params.length == 2 && List.class.isAssignableFrom(params[0])) {
                        m.invoke(target, Collections.singletonList(loc), null);
                        Log.d(TAG, "Delivered location via onLocationChanged(List, Callback) on " + target.getClass().getName());
                        return true;
                    } else if (params.length == 1 && List.class.isAssignableFrom(params[0])) {
                        m.invoke(target, Collections.singletonList(loc));
                        Log.d(TAG, "Delivered location via onLocationChanged(List) on " + target.getClass().getName());
                        return true;
                    } else if (params.length == 1 && Location.class.isAssignableFrom(params[0])) {
                        m.invoke(target, loc);
                        Log.d(TAG, "Delivered location via onLocationChanged(Location) on " + target.getClass().getName());
                        return true;
                    }
                } catch (Throwable ignored) {
                }
            }
        }

        String[] candidateMethods = {"onLocation", "accept", "onLocationChanged"};
        for (String methodName : candidateMethods) {
            try {
                Method m = target.getClass().getMethod(methodName, Location.class);
                m.invoke(target, loc);
                Log.d(TAG, "Delivered location via " + methodName + "(Location) on " + target.getClass().getName());
                return true;
            } catch (Throwable ignored) {
            }
        }

        if (target instanceof IInterface) {
            try {
                BRILocationListener.get((IInterface) target).onLocationChanged(loc);
                Log.d(TAG, "Delivered location via BRILocationListener");
                return true;
            } catch (Throwable ignored) {
            }
        }
        return false;
    }

    private static boolean deliverLocationToCallback(Object callbackObj, Location loc) {
        if (callbackObj == null || loc == null) return false;

        Object target = callbackObj;
        if (callbackObj instanceof IBinder) {
            try {
                Class<?> stubClass = Class.forName("android.location.ILocationCallback$Stub");
                Method asInterface = stubClass.getMethod("asInterface", IBinder.class);
                Object iface = asInterface.invoke(null, callbackObj);
                if (iface != null) {
                    target = iface;
                }
            } catch (Throwable ignored) {
            }
        }
        return invokeLocationOnTarget(target, loc);
    }

    private static IBinder deliverLocationToListener(Object listenerObj, Location loc) {
        if (listenerObj == null || loc == null) return null;
        try {
            if (listenerObj instanceof IInterface) {
                IInterface iface = (IInterface) listenerObj;
                if (invokeLocationOnTarget(iface, loc)) {
                    return iface.asBinder();
                }
            }
            if (listenerObj instanceof IBinder) {
                IBinder binder = (IBinder) listenerObj;
                try {
                    Class<?> stubClass = Class.forName("android.location.ILocationListener$Stub");
                    Method asInterface = stubClass.getMethod("asInterface", IBinder.class);
                    Object converted = asInterface.invoke(null, binder);
                    if (converted != null && invokeLocationOnTarget(converted, loc)) {
                        return binder;
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "Failed delivering location to listener: " + t.getMessage());
        }
        return null;
    }

    public static Location getJitteredSystemLocation() {
        int userId = resolveUserId();
        String pkg = resolvePackageName();
        BLocation bLoc = resolveBLocation();
        if (bLoc == null) {
            Log.w(TAG, "getJitteredSystemLocation: bLoc is null for pkg=" + pkg + ", userId=" + userId);
            return null;
        }

        Location loc = bLoc.convert2SystemLocation();
        if (loc == null) {
            Log.w(TAG, "getJitteredSystemLocation: convert2SystemLocation returned null");
            return null;
        }

        double baseLat = loc.getLatitude();
        double baseLng = loc.getLongitude();

        double radiusInDegrees = 50.0 / 111320.0;
        double u = sRandom.nextDouble();
        double v = sRandom.nextDouble();
        double w = radiusInDegrees * Math.sqrt(u);
        double t = 2 * Math.PI * v;
        double deltaLat = w * Math.cos(t);
        double cosLat = Math.cos(Math.toRadians(baseLat));
        if (Math.abs(cosLat) < 1e-6) {
            cosLat = 1e-6;
        }
        double deltaLng = (w * Math.sin(t)) / cosLat;

        loc.setLatitude(baseLat + deltaLat);
        loc.setLongitude(baseLng + deltaLng);
        loc.setTime(System.currentTimeMillis());
        loc.setElapsedRealtimeNanos(SystemClock.elapsedRealtimeNanos());
        loc.setAccuracy(5.0f + sRandom.nextFloat() * 10.0f);
        clearMockFlags(loc);
        Log.d(TAG, "Jittered location for " + pkg + ": lat=" + loc.getLatitude() + ", lng=" + loc.getLongitude());
        return loc;
    }

    @Override
    public Object invoke(Object proxy, Method method, Object... args) throws Throwable {
        MethodParameterUtils.replaceFirstAppPkg(args);

        String packageName = resolvePackageName();
        String mName = method.getName();

        if (packageName != null && !"top.niunaijun.blackbox".equals(packageName) &&
                (mName.toLowerCase().contains("loc") ||
                 mName.toLowerCase().contains("provider") ||
                 mName.toLowerCase().contains("listener") ||
                 mName.toLowerCase().contains("callback") ||
                 mName.toLowerCase().contains("gnss"))) {
            Log.d(TAG, "ILocationManager call: pkg=" + packageName + ", method=" + mName);
        }

        if ("com.google.android.gms".equals(packageName)) {
            if (mName.equals("getLastLocation") ||
                mName.equals("getLastKnownLocation") ||
                mName.equals("getCurrentLocation") ||
                mName.equals("requestLocationUpdates") ||
                mName.equals("registerLocationListener")) {
                Log.w(TAG, "Blocking location request from Google Play Services: " + mName);
                return null;
            }
        }

        if (shouldSpoofLocation()) {
            if (mName.equals("isLocationEnabled") ||
                mName.equals("isLocationEnabledForUser") ||
                mName.equals("isProviderEnabled") ||
                mName.equals("isProviderEnabledForUser")) {
                Log.d(TAG, "Returning true for " + mName + " in pkg=" + packageName);
                return true;
            }
            if (mName.equals("getLastLocation") || mName.equals("getLastKnownLocation")) {
                Location fakeLoc = getJitteredSystemLocation();
                if (fakeLoc != null) {
                    return fakeLoc;
                }
            }
        }

        try {
            return super.invoke(proxy, method, args);
        } catch (Throwable t) {
            if (t instanceof SecurityException || (t.getCause() instanceof SecurityException)) {
                if (mName.contains("Gnss") || mName.contains("Nmea")) {
                    Log.w(TAG, "Suppressing SecurityException in " + mName + " for " + packageName);
                    return null;
                }
            }
            throw t;
        }
    }

    @ProxyMethod("registerGnssStatusCallback")
    public static class RegisterGnssStatusCallback extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            return true;
        }
    }

    @ProxyMethod("getLastLocation")
    public static class GetLastLocation extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (shouldSpoofLocation()) {
                Log.d(TAG, "Hooked getLastLocation for " + resolvePackageName());
                return getJitteredSystemLocation();
            }
            try {
                return method.invoke(who, args);
            } catch (Exception e) {
                if (e.getCause() instanceof SecurityException) {
                    return null;
                }
                throw e;
            }
        }
    }

    @ProxyMethod("getLastKnownLocation")
    public static class GetLastKnownLocation extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (shouldSpoofLocation()) {
                Log.d(TAG, "Hooked getLastKnownLocation for " + resolvePackageName());
                return getJitteredSystemLocation();
            }
            try {
                return method.invoke(who, args);
            } catch (Exception e) {
                if (e.getCause() instanceof SecurityException) {
                    return null;
                }
                throw e;
            }
        }
    }

    @ProxyMethod("getCurrentLocation")
    public static class GetCurrentLocation extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (shouldSpoofLocation()) {
                Log.d(TAG, "Hooked getCurrentLocation for " + resolvePackageName() + ", args=" + (args != null ? args.length : 0));
                Location fakeLoc = getJitteredSystemLocation();
                if (args != null && fakeLoc != null) {
                    for (Object arg : args) {
                        if (arg != null && deliverLocationToCallback(arg, fakeLoc)) {
                            break;
                        }
                    }
                }
                return createDummyCancellationSignal();
            }
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("requestLocationUpdates")
    public static class RequestLocationUpdates extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (shouldSpoofLocation() && args != null) {
                Log.d(TAG, "Hooked requestLocationUpdates for " + resolvePackageName());
                Location jittered = getJitteredSystemLocation();
                for (Object arg : args) {
                    IBinder binder = deliverLocationToListener(arg, jittered);
                    if (binder != null) {
                        BLocationManager.get().requestLocationUpdates(binder);
                        return 0;
                    }
                }
            }
            try {
                return method.invoke(who, args);
            } catch (Exception e) {
                if (e.getCause() instanceof SecurityException) {
                    return 0;
                }
                throw e;
            }
        }
    }

    @ProxyMethod("registerLocationListener")
    public static class RegisterLocationListener extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (shouldSpoofLocation() && args != null) {
                Log.d(TAG, "Hooked registerLocationListener for " + resolvePackageName() + ", args=" + args.length);
                Location jittered = getJitteredSystemLocation();
                for (Object arg : args) {
                    IBinder binder = deliverLocationToListener(arg, jittered);
                    if (binder != null) {
                        BLocationManager.get().requestLocationUpdates(binder);
                        return null;
                    }
                }
            }
            try {
                return method.invoke(who, args);
            } catch (Exception e) {
                if (e.getCause() instanceof SecurityException) {
                    return null;
                }
                throw e;
            }
        }
    }

    @ProxyMethod("removeUpdates")
    public static class RemoveUpdates extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (args != null && args.length > 0) {
                Object firstArg = Array.get(args, 0);
                if (firstArg instanceof IInterface) {
                    BLocationManager.get().removeUpdates(((IInterface) firstArg).asBinder());
                    return 0;
                } else if (firstArg instanceof IBinder) {
                    BLocationManager.get().removeUpdates((IBinder) firstArg);
                    return 0;
                }
            }
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("unregisterLocationListener")
    public static class UnregisterLocationListener extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (args != null) {
                for (Object arg : args) {
                    if (arg instanceof IInterface) {
                        BLocationManager.get().removeUpdates(((IInterface) arg).asBinder());
                        return null;
                    } else if (arg instanceof IBinder) {
                        BLocationManager.get().removeUpdates((IBinder) arg);
                        return null;
                    }
                }
            }
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("getProviderProperties")
    public static class GetProviderProperties extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            Object providerProperties = method.invoke(who, args);
            if (shouldSpoofLocation() && providerProperties != null) {
                BRProviderProperties.get(providerProperties)._set_mHasNetworkRequirement(false);
                if (BLocationManager.get().getCell(resolveUserId(), resolvePackageName()) == null) {
                    BRProviderProperties.get(providerProperties)._set_mHasCellRequirement(false);
                }
            }
            return providerProperties;
        }
    }

    @ProxyMethod("removeGpsStatusListener")
    public static class RemoveGpsStatusListener extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            return 0;
        }
    }

    @ProxyMethod("getBestProvider")
    public static class GetBestProvider extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (shouldSpoofLocation()) {
                return LocationManager.GPS_PROVIDER;
            }
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("getAllProviders")
    public static class GetAllProviders extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            return Arrays.asList(LocationManager.GPS_PROVIDER, LocationManager.NETWORK_PROVIDER);
        }
    }

    @ProxyMethod("isProviderEnabled")
    public static class IsProviderEnabled extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (shouldSpoofLocation()) {
                return true;
            }
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("isProviderEnabledForUser")
    public static class isProviderEnabledForUser extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (shouldSpoofLocation()) {
                return true;
            }
            String provider = (args != null && args.length > 0 && Array.get(args, 0) instanceof String)
                    ? (String) Array.get(args, 0) : "";
            return LocationManager.GPS_PROVIDER.equals(provider);
        }
    }

    @ProxyMethod("isLocationEnabledForUser")
    public static class IsLocationEnabledForUser extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (shouldSpoofLocation()) {
                Log.d(TAG, "Hooked isLocationEnabledForUser -> true for " + resolvePackageName());
                return true;
            }
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("setExtraLocationControllerPackageEnabled")
    public static class setExtraLocationControllerPackageEnabled extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            return 0;
        }
    }
}