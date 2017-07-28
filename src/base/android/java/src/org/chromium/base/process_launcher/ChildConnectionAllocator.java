// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.process_launcher;

import android.content.ComponentName;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;

import org.chromium.base.Log;
import org.chromium.base.ObserverList;
import org.chromium.base.VisibleForTesting;

import java.util.ArrayList;
import java.util.Arrays;

/**
 * This class is responsible for allocating and managing connections to child
 * process services. These connections are in a pool (the services are defined
 * in the AndroidManifest.xml).
 */
public class ChildConnectionAllocator {
    private static final String TAG = "ChildConnAllocator";

    /** Listener that clients can use to get notified when connections get allocated/freed. */
    public abstract static class Listener {
        /** Called when a connection has been allocated, before it gets bound. */
        public void onConnectionAllocated(
                ChildConnectionAllocator allocator, ChildProcessConnection connection) {}

        /** Called when a connection has been freed. */
        public void onConnectionFreed(
                ChildConnectionAllocator allocator, ChildProcessConnection connection) {}
    }

    /** Factory interface. Used by tests to specialize created connections. */
    @VisibleForTesting
    public interface ConnectionFactory {
        ChildProcessConnection createConnection(Context context, ComponentName serviceName,
                boolean bindToCaller, boolean bindAsExternalService, Bundle serviceBundle);
    }

    /** Default implementation of the ConnectionFactory that creates actual connections. */
    private static class ConnectionFactoryImpl implements ConnectionFactory {
        @Override
        public ChildProcessConnection createConnection(Context context, ComponentName serviceName,
                boolean bindToCaller, boolean bindAsExternalService, Bundle serviceBundle) {
            return new ChildProcessConnection(
                    context, serviceName, bindToCaller, bindAsExternalService, serviceBundle);
        }
    }

    // Delay between the call to freeConnection and the connection actually beeing   freed.
    private static final long FREE_CONNECTION_DELAY_MILLIS = 1;

    // The handler of the thread on which all interations should happen.
    private final Handler mLauncherHandler;

    // Connections to services. Indices of the array correspond to the service numbers.
    private final ChildProcessConnection[] mChildProcessConnections;

    private final String mPackageName;
    private final String mServiceClassName;
    private final boolean mBindToCaller;
    private final boolean mBindAsExternalService;
    private final boolean mUseStrongBinding;

    // The list of free (not bound) service indices.
    private final ArrayList<Integer> mFreeConnectionIndices;

    private final ObserverList<Listener> mListeners = new ObserverList<>();

    private ConnectionFactory mConnectionFactory = new ConnectionFactoryImpl();

    /**
     * Factory method that retrieves the service name and number of service from the
     * AndroidManifest.xml.
     */
    public static ChildConnectionAllocator create(Context context, Handler launcherHandler,
            String packageName, String serviceClassNameManifestKey,
            String numChildServicesManifestKey, boolean bindToCaller, boolean bindAsExternalService,
            boolean useStrongBinding) {
        String serviceClassName = null;
        int numServices = -1;
        PackageManager packageManager = context.getPackageManager();
        try {
            ApplicationInfo appInfo =
                    packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA);
            if (appInfo.metaData != null) {
                serviceClassName = appInfo.metaData.getString(serviceClassNameManifestKey);
                numServices = appInfo.metaData.getInt(numChildServicesManifestKey, -1);
            }
        } catch (PackageManager.NameNotFoundException e) {
            throw new RuntimeException("Could not get application info.");
        }

        if (numServices < 0) {
            throw new RuntimeException("Illegal meta data value for number of child services");
        }

        // Check that the service exists.
        try {
            // PackageManager#getServiceInfo() throws an exception if the service does not exist.
            packageManager.getServiceInfo(
                    new ComponentName(packageName, serviceClassName + "0"), 0);
        } catch (PackageManager.NameNotFoundException e) {
            throw new RuntimeException("Illegal meta data value: the child service doesn't exist");
        }

        return new ChildConnectionAllocator(launcherHandler, packageName, serviceClassName,
                bindToCaller, bindAsExternalService, useStrongBinding, numServices);
    }

    // TODO(jcivelli): remove this method once crbug.com/693484 has been addressed.
    public static int getNumberOfServices(
            Context context, String packageName, String numChildServicesManifestKey) {
        int numServices = -1;
        try {
            PackageManager packageManager = context.getPackageManager();
            ApplicationInfo appInfo =
                    packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA);
            if (appInfo.metaData != null) {
                numServices = appInfo.metaData.getInt(numChildServicesManifestKey, -1);
            }
        } catch (PackageManager.NameNotFoundException e) {
            throw new RuntimeException("Could not get application info", e);
        }
        if (numServices < 0) {
            throw new RuntimeException("Illegal meta data value for number of child services");
        }
        return numServices;
    }

    /**
     * Factory method used with some tests to create an allocator with values passed in directly
     * instead of being retrieved from the AndroidManifest.xml.
     */
    @VisibleForTesting
    public static ChildConnectionAllocator createForTest(String packageName,
            String serviceClassName, int serviceCount, boolean bindToCaller,
            boolean bindAsExternalService, boolean useStrongBinding) {
        return new ChildConnectionAllocator(new Handler(), packageName, serviceClassName,
                bindToCaller, bindAsExternalService, useStrongBinding, serviceCount);
    }

    private ChildConnectionAllocator(Handler launcherHandler, String packageName,
            String serviceClassName, boolean bindToCaller, boolean bindAsExternalService,
            boolean useStrongBinding, int numChildServices) {
        mLauncherHandler = launcherHandler;
        assert isRunningOnLauncherThread();
        mPackageName = packageName;
        mServiceClassName = serviceClassName;
        mBindToCaller = bindToCaller;
        mBindAsExternalService = bindAsExternalService;
        mUseStrongBinding = useStrongBinding;
        mChildProcessConnections = new ChildProcessConnection[numChildServices];
        mFreeConnectionIndices = new ArrayList<Integer>(numChildServices);
        for (int i = 0; i < numChildServices; i++) {
            mFreeConnectionIndices.add(i);
        }
    }

    /** @return a bound connection, or null if there are no free slots. */
    public ChildProcessConnection allocate(Context context, Bundle serviceBundle,
            final ChildProcessConnection.ServiceCallback serviceCallback) {
        assert isRunningOnLauncherThread();
        if (mFreeConnectionIndices.isEmpty()) {
            Log.d(TAG, "Ran out of services to allocate.");
            return null;
        }
        int slot = mFreeConnectionIndices.remove(0);
        assert mChildProcessConnections[slot] == null;
        ComponentName serviceName = new ComponentName(mPackageName, mServiceClassName + slot);

        // Wrap the service callbacks so that:
        // - we can intercept onChildProcessDied and clean-up connections
        // - the callbacks are actually posted so that this method will return before the callbacks
        //   are called (so that the caller may set any reference to the returned connection before
        //   any callback logic potentially tries to access that connection).
        ChildProcessConnection.ServiceCallback serviceCallbackWrapper =
                new ChildProcessConnection.ServiceCallback() {
                    @Override
                    public void onChildStarted() {
                        assert isRunningOnLauncherThread();
                        if (serviceCallback != null) {
                            mLauncherHandler.post(new Runnable() {
                                @Override
                                public void run() {
                                    serviceCallback.onChildStarted();
                                }
                            });
                        }
                    }

                    @Override
                    public void onChildStartFailed(final ChildProcessConnection connection) {
                        assert isRunningOnLauncherThread();
                        if (serviceCallback != null) {
                            mLauncherHandler.post(new Runnable() {
                                @Override
                                public void run() {
                                    serviceCallback.onChildStartFailed(connection);
                                }
                            });
                        }
                        freeConnectionWithDelay(connection);
                    }

                    @Override
                    public void onChildProcessDied(final ChildProcessConnection connection) {
                        assert isRunningOnLauncherThread();
                        if (serviceCallback != null) {
                            mLauncherHandler.post(new Runnable() {
                                @Override
                                public void run() {
                                    serviceCallback.onChildProcessDied(connection);
                                }
                            });
                        }
                        freeConnectionWithDelay(connection);
                    }

                    private void freeConnectionWithDelay(final ChildProcessConnection connection) {
                        // Freeing a service should be delayed. This is so that we avoid immediately
                        // reusing the freed service (see http://crbug.com/164069): the framework
                        // might keep a service process alive when it's been unbound for a short
                        // time. If a new connection to the same service is bound at that point, the
                        // process is reused and bad things happen (mostly static variables are set
                        // when we don't expect them to).
                        mLauncherHandler.postDelayed(new Runnable() {
                            @Override
                            public void run() {
                                free(connection);
                            }
                        }, FREE_CONNECTION_DELAY_MILLIS);
                    }
                };

        ChildProcessConnection connection = mConnectionFactory.createConnection(
                context, serviceName, mBindToCaller, mBindAsExternalService, serviceBundle);
        mChildProcessConnections[slot] = connection;

        for (Listener listener : mListeners) {
            listener.onConnectionAllocated(this, connection);
        }

        connection.start(mUseStrongBinding, serviceCallbackWrapper, false /* retryOnTimeout */);
        Log.d(TAG, "Allocator allocated and bound a connection, name: %s, slot: %d",
                mServiceClassName, slot);
        return connection;
    }

    /** Frees a connection and notifies listeners. */
    private void free(ChildProcessConnection connection) {
        assert isRunningOnLauncherThread();

        // mChildProcessConnections is relatively short (20 items at max at this point).
        // We are better of iterating than caching in a map.
        int slot = Arrays.asList(mChildProcessConnections).indexOf(connection);
        if (slot == -1) {
            Log.e(TAG, "Unable to find connection to free.");
            assert false;
        } else {
            mChildProcessConnections[slot] = null;
            assert !mFreeConnectionIndices.contains(slot);
            mFreeConnectionIndices.add(slot);
            Log.d(TAG, "Allocator freed a connection, name: %s, slot: %d", mServiceClassName, slot);
        }

        for (Listener listener : mListeners) {
            listener.onConnectionFreed(this, connection);
        }
    }

    public String getPackageName() {
        return mPackageName;
    }

    public boolean anyConnectionAllocated() {
        return mFreeConnectionIndices.size() < mChildProcessConnections.length;
    }

    public boolean isFreeConnectionAvailable() {
        assert isRunningOnLauncherThread();
        return !mFreeConnectionIndices.isEmpty();
    }

    public int getNumberOfServices() {
        return mChildProcessConnections.length;
    }

    public void addListener(Listener listener) {
        assert !mListeners.hasObserver(listener);
        mListeners.addObserver(listener);
    }

    public void removeListener(Listener listener) {
        boolean removed = mListeners.removeObserver(listener);
        assert removed;
    }

    @VisibleForTesting
    public void setConnectionFactoryForTesting(ConnectionFactory connectionFactory) {
        mConnectionFactory = connectionFactory;
    }

    /** @return the count of connections managed by the allocator */
    @VisibleForTesting
    public int allocatedConnectionsCountForTesting() {
        assert isRunningOnLauncherThread();
        return mChildProcessConnections.length - mFreeConnectionIndices.size();
    }

    @VisibleForTesting
    public ChildProcessConnection getChildProcessConnectionAtSlotForTesting(int slotNumber) {
        return mChildProcessConnections[slotNumber];
    }

    private boolean isRunningOnLauncherThread() {
        return mLauncherHandler.getLooper() == Looper.myLooper();
    }
}
