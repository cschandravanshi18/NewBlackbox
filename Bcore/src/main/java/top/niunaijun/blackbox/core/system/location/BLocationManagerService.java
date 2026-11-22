package top.niunaijun.blackbox.core.system.location;

import android.location.Location;
import android.os.Build;
import android.os.IBinder;
import android.os.IInterface;
import android.os.Parcel;
import android.os.RemoteException;
import android.os.SystemClock;
import android.util.AtomicFile;
import android.util.SparseArray;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import black.android.location.BRILocationListener;
import black.android.location.BRILocationListenerStub;
import top.niunaijun.blackbox.BlackBoxCore;
import top.niunaijun.blackbox.core.env.BEnvironment;
import top.niunaijun.blackbox.core.system.ISystemService;
import top.niunaijun.blackbox.entity.location.BCell;
import top.niunaijun.blackbox.entity.location.BLocation;
import top.niunaijun.blackbox.entity.location.BLocationConfig;
import top.niunaijun.blackbox.fake.frameworks.BLocationManager;
import top.niunaijun.blackbox.utils.CloseUtils;
import top.niunaijun.blackbox.utils.FileUtils;
import top.niunaijun.blackbox.utils.Slog;

public class BLocationManagerService extends IBLocationManagerService.Stub implements ISystemService {
    public static final String TAG = "BLocationManagerService";

    private static final BLocationManagerService sService = new BLocationManagerService();
    private final SparseArray<HashMap<String, BLocationConfig>> mLocationConfigs = new SparseArray<>();
    private final BLocationConfig mGlobalConfig = new BLocationConfig();
    private final Map<IBinder, LocationRecord> mLocationListeners = new HashMap<>();
    private final Executor mThreadPool = Executors.newCachedThreadPool();
    private final Random mRandom = new Random();

    public static BLocationManagerService get() {
        return sService;
    }

    private BLocationConfig getOrCreateConfig(int userId, String pkg) {
        synchronized (mLocationConfigs) {
            HashMap<String, BLocationConfig> pkgs = mLocationConfigs.get(userId);
            if (pkgs == null) {
                pkgs = new HashMap<>();
                mLocationConfigs.put(userId, pkgs);
            }
            BLocationConfig config = pkgs.get(pkg);
            if (config == null) {
                config = new BLocationConfig();
                config.pattern = BLocationManager.CLOSE_MODE;
                pkgs.put(pkg, config);
            }
            return config;
        }
    }

    public int getPattern(int userId, String pkg) {
        synchronized (mLocationConfigs) {
            BLocationConfig config = getOrCreateConfig(userId, pkg);
            return config.pattern;
        }
    }

    @Override
    public void setPattern(int userId, String pkg, int pattern) {
        synchronized (mLocationConfigs) {
            getOrCreateConfig(userId, pkg).pattern = pattern;
            save();
        }
    }

    @Override
    public void setCell(int userId, String pkg, BCell cell) {
        synchronized (mLocationConfigs) {
            getOrCreateConfig(userId, pkg).cell = cell;
            save();
        }
    }

    @Override
    public void setAllCell(int userId, String pkg, List<BCell> cells) {
        synchronized (mLocationConfigs) {
            getOrCreateConfig(userId, pkg).allCell = cells;
            save();
        }
    }

    @Override
    public void setNeighboringCell(int userId, String pkg, List<BCell> cells) {
        synchronized (mLocationConfigs) {
            getOrCreateConfig(userId, pkg).allCell = cells;
            save();
        }
    }

    @Override
    public List<BCell> getNeighboringCell(int userId, String pkg) {
        synchronized (mLocationConfigs) {
            return getOrCreateConfig(userId, pkg).allCell;
        }
    }

    @Override
    public void setGlobalCell(BCell cell) {
        synchronized (mGlobalConfig) {
            mGlobalConfig.cell = cell;
            save();
        }
    }

    @Override
    public void setGlobalAllCell(List<BCell> cells) {
        synchronized (mGlobalConfig) {
            mGlobalConfig.allCell = cells;
            save();
        }
    }

    @Override
    public void setGlobalNeighboringCell(List<BCell> cells) {
        synchronized (mGlobalConfig) {
            mGlobalConfig.neighboringCellInfo = cells;
            save();
        }
    }

    @Override
    public List<BCell> getGlobalNeighboringCell() {
        synchronized (mGlobalConfig) {
            return mGlobalConfig.neighboringCellInfo;
        }
    }

    @Override
    public BCell getCell(int userId, String pkg) {
        BLocationConfig config = getOrCreateConfig(userId, pkg);
        switch (config.pattern) {
            case BLocationManager.OWN_MODE:
                return config.cell;
            case BLocationManager.GLOBAL_MODE:
                return mGlobalConfig.cell;
            case BLocationManager.CLOSE_MODE:
            default:
                return null;
        }
    }

    @Override
    public List<BCell> getAllCell(int userId, String pkg) {
        BLocationConfig config = getOrCreateConfig(userId, pkg);
        switch (config.pattern) {
            case BLocationManager.OWN_MODE:
                return config.allCell;
            case BLocationManager.GLOBAL_MODE:
                return mGlobalConfig.allCell;
            case BLocationManager.CLOSE_MODE:
            default:
                return null;
        }
    }

    @Override
    public void setLocation(int userId, String pkg, BLocation location) {
        synchronized (mLocationConfigs) {
            getOrCreateConfig(userId, pkg).location = location;
            save();
        }
    }

    @Override
    public BLocation getLocation(int userId, String pkg) {
        BLocationConfig config = getOrCreateConfig(userId, pkg);
        switch (config.pattern) {
            case BLocationManager.OWN_MODE:
                return config.location != null ? config.location : mGlobalConfig.location;
            case BLocationManager.GLOBAL_MODE:
                return mGlobalConfig.location;
            case BLocationManager.CLOSE_MODE:
            default:
                return null;
        }
    }

    @Override
    public void setGlobalLocation(BLocation location) {
        synchronized (mGlobalConfig) {
            mGlobalConfig.location = location;
            save();
        }
    }

    @Override
    public BLocation getGlobalLocation() {
        synchronized (mGlobalConfig) {
            return mGlobalConfig.location;
        }
    }

    @Override
    public void requestLocationUpdates(IBinder listener, String packageName, int userId) throws RemoteException {
        if (listener == null || !listener.pingBinder()) {
            return;
        }
        synchronized (mLocationListeners) {
            if (mLocationListeners.containsKey(listener))
                return;
            listener.linkToDeath(new DeathRecipient() {
                @Override
                public void binderDied() {
                    listener.unlinkToDeath(this, 0);
                    synchronized (mLocationListeners) {
                        mLocationListeners.remove(listener);
                    }
                }
            }, 0);
            LocationRecord record = new LocationRecord(packageName, userId);
            mLocationListeners.put(listener, record);
        }
        addTask(listener);
    }

    @Override
    public void removeUpdates(IBinder listener) throws RemoteException {
        if (listener == null) {
            return;
        }
        synchronized (mLocationListeners) {
            mLocationListeners.remove(listener);
        }
    }

    private Location createJitteredLocation(BLocation base) {
        Location loc = base.convert2SystemLocation();
        double baseLat = loc.getLatitude();
        double baseLng = loc.getLongitude();

        double radiusInDegrees = 50.0 / 111320.0;
        double u = mRandom.nextDouble();
        double v = mRandom.nextDouble();
        double w = radiusInDegrees * Math.sqrt(u);
        double t = 2.0 * Math.PI * v;
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
        loc.setAccuracy(5.0f + mRandom.nextFloat() * 10.0f);

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
        return loc;
    }

    private static void dispatchLocationToBinder(IBinder locationListener, Location jittered) {
        IInterface iInterface = BRILocationListenerStub.get().asInterface(locationListener);
        if (iInterface == null) return;

        for (Method m : iInterface.getClass().getMethods()) {
            if ("onLocationChanged".equals(m.getName())) {
                Class<?>[] params = m.getParameterTypes();
                try {
                    if (params.length == 2 && List.class.isAssignableFrom(params[0])) {
                        m.invoke(iInterface, Collections.singletonList(jittered), null);
                        return;
                    } else if (params.length == 1 && List.class.isAssignableFrom(params[0])) {
                        m.invoke(iInterface, Collections.singletonList(jittered));
                        return;
                    } else if (params.length == 1 && Location.class.isAssignableFrom(params[0])) {
                        m.invoke(iInterface, jittered);
                        return;
                    }
                } catch (Throwable ignored) {
                }
            }
        }

        try {
            BRILocationListener.get(iInterface).onLocationChanged(jittered);
        } catch (Throwable ignored) {
        }
    }

    private void addTask(IBinder locationListener) {
        mThreadPool.execute(() -> {
            long lastSent = 0L;
            while (locationListener.pingBinder()) {
                LocationRecord locationRecord;
                synchronized (mLocationListeners) {
                    locationRecord = mLocationListeners.get(locationListener);
                }
                if (locationRecord == null) {
                    break;
                }
                BLocation location = getLocation(locationRecord.userId, locationRecord.packageName);
                if (location == null) {
                    location = getGlobalLocation();
                }
                if (location == null) {
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException ignored) {
                    }
                    continue;
                }
                if ((System.currentTimeMillis() - lastSent) < 2000) {
                    try {
                        Thread.sleep(500);
                    } catch (InterruptedException ignored) {
                    }
                    continue;
                }
                lastSent = System.currentTimeMillis();
                Location jittered = createJitteredLocation(location);
                BlackBoxCore.get().getHandler().post(() -> dispatchLocationToBinder(locationListener, jittered));
            }
        });
    }

    public void save() {
        synchronized (mGlobalConfig) {
            synchronized (mLocationConfigs) {
                Parcel parcel = Parcel.obtain();
                AtomicFile atomicFile = new AtomicFile(BEnvironment.getFakeLocationConf());
                FileOutputStream fileOutputStream = null;
                try {
                    mGlobalConfig.writeToParcel(parcel, 0);

                    parcel.writeInt(mLocationConfigs.size());
                    for (int i = 0; i < mLocationConfigs.size(); i++) {
                        int tmpUserId = mLocationConfigs.keyAt(i);
                        HashMap<String, BLocationConfig> configArrayMap = mLocationConfigs.valueAt(i);
                        parcel.writeInt(tmpUserId);
                        parcel.writeMap(configArrayMap);
                    }
                    parcel.setDataPosition(0);
                    fileOutputStream = atomicFile.startWrite();
                    FileUtils.writeParcelToOutput(parcel, fileOutputStream);
                    atomicFile.finishWrite(fileOutputStream);
                } catch (Throwable e) {
                    e.printStackTrace();
                    atomicFile.failWrite(fileOutputStream);
                } finally {
                    parcel.recycle();
                    CloseUtils.close(fileOutputStream);
                }
            }
        }
    }

    public void loadConfig() {
        Parcel parcel = Parcel.obtain();
        InputStream is = null;
        try {
            File fakeLocationConf = BEnvironment.getFakeLocationConf();
            if (!fakeLocationConf.exists()) {
                return;
            }
            is = new FileInputStream(BEnvironment.getFakeLocationConf());
            byte[] bytes = FileUtils.toByteArray(is);
            parcel.unmarshall(bytes, 0, bytes.length);
            parcel.setDataPosition(0);

            synchronized (mGlobalConfig) {
                mGlobalConfig.refresh(parcel);
            }

            synchronized (mLocationConfigs) {
                mLocationConfigs.clear();
                int size = parcel.readInt();
                for (int i = 0; i < size; i++) {
                    int userId = parcel.readInt();
                    HashMap<String, BLocationConfig> configArrayMap = parcel.readHashMap(BLocationConfig.class.getClassLoader());
                    mLocationConfigs.put(userId, configArrayMap);
                    Slog.d(TAG, "load userId: " + userId + ", config: " + configArrayMap);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            Slog.d(TAG, "bad config");
            FileUtils.deleteDir(BEnvironment.getFakeLocationConf());
        } finally {
            parcel.recycle();
            CloseUtils.close(is);
        }
    }

    @Override
    public void systemReady() {
        loadConfig();
        synchronized (mLocationListeners) {
            for (IBinder iBinder : mLocationListeners.keySet()) {
                addTask(iBinder);
            }
        }
    }
}