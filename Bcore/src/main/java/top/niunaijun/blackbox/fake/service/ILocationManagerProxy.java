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
import java.util.Random;

import black.android.location.BRILocationListener;
import black.android.location.BRILocationManagerStub;
import black.android.location.provider.BRProviderProperties;
import black.android.os.BRServiceManager;
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
        return false;
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

    private static void deliverLocationToCallback(Object callbackObj, Location loc) {
        if (callbackObj == null || loc == null) return;

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

        String[] candidateMethods = {"onLocation", "accept", "onLocationChanged"};
        for (String methodName : candidateMethods) {
            try {
                Method m = target.getClass().getMethod(methodName, Location.class);
                m.invoke(target, loc);
                Log.d(TAG, "Delivered location via callback method: " + methodName + " on " + target.getClass().getName());
                return;
            } catch (Throwable ignored) {
            }
        }
    }

    private static void deliverLocationToListener(Object listenerObj, Location loc) {
        if (listenerObj == null || loc == null) return;
        try {
            if (listenerObj instanceof IInterface) {
                BRILocationListener.get((IInterface) listenerObj).onLocationChanged(loc);
                Log.d(TAG, "Delivered location via BRILocationListener");
                return;
            }
            if (listenerObj instanceof IBinder) {
                IInterface iface = BRILocationListener.get(listenerObj) != null
                        ? (IInterface) listenerObj
                        : null;
                try {
                    Class<?> stubClass = Class.forName("android.location.ILocationListener$Stub");
                    Method asInterface = stubClass.getMethod("asInterface", IBinder.class);
                    Object converted = asInterface.invoke(null, listenerObj);
                    if (converted instanceof IInterface) {
                        BRILocationListener.get((IInterface) converted).onLocationChanged(loc);
                        Log.d(TAG, "Delivered location via ILocationListener.Stub.asInterface");
                        return;
                    }
                } catch (Throwable ignored) {
                }
            }
        } catch (Throwable t) {
            Log.w(TAG, "Failed delivering location to listener: " + t.getMessage());
        }
    }

    public static Location getJitteredSystemLocation() {
        int userId = BActivityThread.getUserId();
        String pkg = BActivityThread.getAppPackageName();
        BLocation bLoc = BLocationManager.get().getLocation(userId, pkg);
        if (bLoc == null) {
            bLoc = BLocationManager.get().getGlobalLocation();
        }
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

        String packageName = BActivityThread.getAppPackageName();
        String mName = method.getName();
        
        
        // my additional....//
        
        if ("com.vsk_teacher_attendance".equals(packageName) &&
                (mName.toLowerCase().contains("loc") ||
                 mName.toLowerCase().contains("provider") ||
                 mName.toLowerCase().contains("listener") ||
                 mName.toLowerCase().contains("callback"))) {
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

        //end......//





        
        if (packageName != null && packageName.equals("com.google.android.gms")) {
            if (mName.equals("getLastLocation") ||
                mName.equals("getLastKnownLocation") ||
                mName.equals("getCurrentLocation") ||
                mName.equals("requestLocationUpdates") ||
                mName.equals("registerLocationListener")) {
                Log.w(TAG, "Blocking location request from Google Play Services: " + mName);
                return null;
            }
        }

        boolean fakeEnabled = BLocationManager.isFakeLocationEnable();
        if (fakeEnabled) {
            if (mName.equals("isLocationEnabled") ||
                mName.equals("isLocationEnabledForUser") ||
                mName.equals("isProviderEnabled") ||
                mName.equals("isProviderEnabledForUser")) {
                Log.d(TAG, "Returning true for " + mName + " in pkg=" + packageName);
                return true;
            }
        }

        return super.invoke(proxy, method, args);
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
            if (BLocationManager.isFakeLocationEnable()) {
                Log.d(TAG, "Hooked getLastLocation for " + BActivityThread.getAppPackageName());
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
            if (BLocationManager.isFakeLocationEnable()) {
                Log.d(TAG, "Hooked getLastKnownLocation for " + BActivityThread.getAppPackageName());
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
            if (BLocationManager.isFakeLocationEnable()) {
                Log.d(TAG, "Hooked getCurrentLocation for " + BActivityThread.getAppPackageName() + ", args=" + (args != null ? args.length : 0));
                Location fakeLoc = getJitteredSystemLocation();
                if (args != null && fakeLoc != null) {
                    for (Object arg : args) {
                        if (arg != null) {
                            deliverLocationToCallback(arg, fakeLoc);
                        }
                    }
                }
                return null;
            }
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("requestLocationUpdates")
    public static class RequestLocationUpdates extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (BLocationManager.isFakeLocationEnable() && args != null) {
                Log.d(TAG, "Hooked requestLocationUpdates for " + BActivityThread.getAppPackageName());
                Location jittered = getJitteredSystemLocation();
                for (Object arg : args) {
                    if (arg instanceof IInterface) {
                        IInterface listener = (IInterface) arg;
                        BLocationManager.get().requestLocationUpdates(listener.asBinder());
                        if (jittered != null) {
                            deliverLocationToListener(listener, jittered);
                        }
                        return 0;
                    } else if (arg instanceof IBinder) {
                        BLocationManager.get().requestLocationUpdates((IBinder) arg);
                        if (jittered != null) {
                            deliverLocationToListener(arg, jittered);
                        }
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
            if (BLocationManager.isFakeLocationEnable() && args != null) {
                Log.d(TAG, "Hooked registerLocationListener for " + BActivityThread.getAppPackageName());
                Location jittered = getJitteredSystemLocation();
                for (Object arg : args) {
                    if (arg instanceof IInterface) {
                        IInterface listener = (IInterface) arg;
                        BLocationManager.get().requestLocationUpdates(listener.asBinder());
                        if (jittered != null) {
                            deliverLocationToListener(listener, jittered);
                        }
                        return null;
                    } else if (arg instanceof IBinder) {
                        BLocationManager.get().requestLocationUpdates((IBinder) arg);
                        if (jittered != null) {
                            deliverLocationToListener(arg, jittered);
                        }
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
            if (BLocationManager.isFakeLocationEnable() && providerProperties != null) {
                BRProviderProperties.get(providerProperties)._set_mHasNetworkRequirement(false);
                if (BLocationManager.get().getCell(BActivityThread.getUserId(), BActivityThread.getAppPackageName()) == null) {
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
            if (BLocationManager.isFakeLocationEnable()) {
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
            if (BLocationManager.isFakeLocationEnable()) {
                return true;
            }
            return method.invoke(who, args);
        }
    }

    @ProxyMethod("isProviderEnabledForUser")
    public static class isProviderEnabledForUser extends MethodHook {
        @Override
        protected Object hook(Object who, Method method, Object... args) throws Throwable {
            if (BLocationManager.isFakeLocationEnable()) {
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
            if (BLocationManager.isFakeLocationEnable()) {
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
