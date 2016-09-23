// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net;

import android.content.Context;

import org.chromium.base.ObserverList;
import org.chromium.base.VisibleForTesting;
import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;
import org.chromium.base.annotations.NativeClassQualifiedName;

import java.util.ArrayList;

/**
 * Triggers updates to the underlying network state in Chrome.
 *
 * By default, connectivity is assumed and changes must pushed from the embedder via the
 * forceConnectivityState function.
 * Embedders may choose to have this class auto-detect changes in network connectivity by invoking
 * the setAutoDetectConnectivityState function.
 *
 * WARNING: This class is not thread-safe.
 */
@JNINamespace("net")
public class NetworkChangeNotifier {
    /**
     * Alerted when the connection type of the network changes.
     * The alert is fired on the UI thread.
     */
    public interface ConnectionTypeObserver {
        public void onConnectionTypeChanged(int connectionType);
    }

    private final Context mContext;
    private final ArrayList<Long> mNativeChangeNotifiers;
    private final ObserverList<ConnectionTypeObserver> mConnectionTypeObservers;
    private NetworkChangeNotifierAutoDetect mAutoDetector;
    private int mCurrentConnectionType = ConnectionType.CONNECTION_UNKNOWN;
    private double mCurrentMaxBandwidth = Double.POSITIVE_INFINITY;
    private int mMaxBandwidthConnectionType = mCurrentConnectionType;

    private static NetworkChangeNotifier sInstance;

    @VisibleForTesting
    protected NetworkChangeNotifier(Context context) {
        mContext = context.getApplicationContext();
        mNativeChangeNotifiers = new ArrayList<Long>();
        mConnectionTypeObservers = new ObserverList<ConnectionTypeObserver>();
    }

    /**
     * Initializes the singleton once.
     */
    @CalledByNative
    public static NetworkChangeNotifier init(Context context) {
        if (sInstance == null) {
            sInstance = new NetworkChangeNotifier(context);
        }
        return sInstance;
    }

    public static boolean isInitialized() {
        return sInstance != null;
    }

    static void resetInstanceForTests(NetworkChangeNotifier notifier) {
        sInstance = notifier;
    }

    @CalledByNative
    public int getCurrentConnectionType() {
        return mCurrentConnectionType;
    }

    @CalledByNative
    public int getCurrentConnectionSubtype() {
        return mAutoDetector == null
                ? ConnectionSubtype.SUBTYPE_UNKNOWN
                : mAutoDetector.getCurrentConnectionSubtype(mAutoDetector.getCurrentNetworkState());
    }

    @CalledByNative
    public double getCurrentMaxBandwidthInMbps() {
        return mCurrentMaxBandwidth;
    }

    /**
     * Returns NetID of device's current default connected network used for
     * communication. Only available on Lollipop and newer releases and when
     * auto-detection has been enabled, returns NetId.INVALID otherwise.
     */
    @CalledByNative
    public long getCurrentDefaultNetId() {
        return mAutoDetector == null ? NetId.INVALID : mAutoDetector.getDefaultNetId();
    }

    /**
     * Returns an array of all of the device's currently connected
     * networks and ConnectionTypes. Array elements are a repeated sequence of:
     *   NetID of network
     *   ConnectionType of network
     * Only available on Lollipop and newer releases and when auto-detection has
     * been enabled.
     */
    @CalledByNative
    public long[] getCurrentNetworksAndTypes() {
        return mAutoDetector == null ? new long[0] : mAutoDetector.getNetworksAndTypes();
    }

    /**
     * Calls a native map lookup of subtype to max bandwidth.
     */
    public static double getMaxBandwidthForConnectionSubtype(int subtype) {
        return nativeGetMaxBandwidthForConnectionSubtype(subtype);
    }

    /**
     * Adds a native-side observer.
     */
    @CalledByNative
    public void addNativeObserver(long nativeChangeNotifier) {
        mNativeChangeNotifiers.add(nativeChangeNotifier);
    }

    /**
     * Removes a native-side observer.
     */
    @CalledByNative
    public void removeNativeObserver(long nativeChangeNotifier) {
        mNativeChangeNotifiers.remove(nativeChangeNotifier);
    }

    /**
     * Returns the singleton instance.
     */
    public static NetworkChangeNotifier getInstance() {
        assert sInstance != null;
        return sInstance;
    }

    /**
     * Enables auto detection of the current network state based on notifications from the system.
     * Note that passing true here requires the embedding app have the platform ACCESS_NETWORK_STATE
     * permission. Also note that in this case the auto detection is enabled based on the status of
     * the application (@see ApplicationStatus).
     *
     * @param shouldAutoDetect true if the NetworkChangeNotifier should listen for system changes in
     *    network connectivity.
     */
    public static void setAutoDetectConnectivityState(boolean shouldAutoDetect) {
        getInstance().setAutoDetectConnectivityStateInternal(
                shouldAutoDetect, new RegistrationPolicyApplicationStatus());
    }

    /**
     * Registers to always receive network change notifications no matter if
     * the app is in the background or foreground.
     * Note that in normal circumstances, chrome embedders should use
     * {@code setAutoDetectConnectivityState} to listen to network changes only
     * when the app is in the foreground, because network change observers
     * might perform expensive work depending on the network connectivity.
     */
    public static void registerToReceiveNotificationsAlways() {
        getInstance().setAutoDetectConnectivityStateInternal(
                true, new RegistrationPolicyAlwaysRegister());
    }

    /**
     * Registers to receive network change notification based on the provided registration policy.
     */
    public static void setAutoDetectConnectivityState(
            NetworkChangeNotifierAutoDetect.RegistrationPolicy policy) {
        getInstance().setAutoDetectConnectivityStateInternal(true, policy);
    }

    private void destroyAutoDetector() {
        if (mAutoDetector != null) {
            mAutoDetector.destroy();
            mAutoDetector = null;
        }
    }

    private void setAutoDetectConnectivityStateInternal(
            boolean shouldAutoDetect, NetworkChangeNotifierAutoDetect.RegistrationPolicy policy) {
        if (shouldAutoDetect) {
            if (mAutoDetector == null) {
                mAutoDetector = new NetworkChangeNotifierAutoDetect(
                        new NetworkChangeNotifierAutoDetect.Observer() {
                            @Override
                            public void onConnectionTypeChanged(int newConnectionType) {
                                updateCurrentConnectionType(newConnectionType);
                            }
                            @Override
                            public void onMaxBandwidthChanged(double maxBandwidthMbps) {
                                updateCurrentMaxBandwidth(maxBandwidthMbps);
                            }
                            @Override
                            public void onNetworkConnect(long netId, int connectionType) {
                                notifyObserversOfNetworkConnect(netId, connectionType);
                            }
                            @Override
                            public void onNetworkSoonToDisconnect(long netId) {
                                notifyObserversOfNetworkSoonToDisconnect(netId);
                            }
                            @Override
                            public void onNetworkDisconnect(long netId) {
                                notifyObserversOfNetworkDisconnect(netId);
                            }
                            @Override
                            public void purgeActiveNetworkList(long[] activeNetIds) {
                                notifyObserversToPurgeActiveNetworkList(activeNetIds);
                            }
                        },
                        mContext, policy);
                final NetworkChangeNotifierAutoDetect.NetworkState networkState =
                        mAutoDetector.getCurrentNetworkState();
                updateCurrentConnectionType(mAutoDetector.getCurrentConnectionType(networkState));
                updateCurrentMaxBandwidth(mAutoDetector.getCurrentMaxBandwidthInMbps(networkState));
            }
        } else {
            destroyAutoDetector();
        }
    }

    /**
     * Updates the perceived network state when not auto-detecting changes to connectivity.
     *
     * @param networkAvailable True if the NetworkChangeNotifier should perceive a "connected"
     *    state, false implies "disconnected".
     */
    @CalledByNative
    public static void forceConnectivityState(boolean networkAvailable) {
        setAutoDetectConnectivityState(false);
        getInstance().forceConnectivityStateInternal(networkAvailable);
    }

    private void forceConnectivityStateInternal(boolean forceOnline) {
        boolean connectionCurrentlyExists =
                mCurrentConnectionType != ConnectionType.CONNECTION_NONE;
        if (connectionCurrentlyExists != forceOnline) {
            updateCurrentConnectionType(forceOnline ? ConnectionType.CONNECTION_UNKNOWN
                    : ConnectionType.CONNECTION_NONE);
            updateCurrentMaxBandwidth(forceOnline ? Double.POSITIVE_INFINITY : 0.0);
        }
    }

    // For testing, pretend a network connected.
    @CalledByNative
    public static void fakeNetworkConnected(long netId, int connectionType) {
        setAutoDetectConnectivityState(false);
        getInstance().notifyObserversOfNetworkConnect(netId, connectionType);
    }

    // For testing, pretend a network will soon disconnect.
    @CalledByNative
    public static void fakeNetworkSoonToBeDisconnected(long netId) {
        setAutoDetectConnectivityState(false);
        getInstance().notifyObserversOfNetworkSoonToDisconnect(netId);
    }

    // For testing, pretend a network disconnected.
    @CalledByNative
    public static void fakeNetworkDisconnected(long netId) {
        setAutoDetectConnectivityState(false);
        getInstance().notifyObserversOfNetworkDisconnect(netId);
    }

    // For testing, pretend a network lists should be purged.
    @CalledByNative
    public static void fakePurgeActiveNetworkList(long[] activeNetIds) {
        setAutoDetectConnectivityState(false);
        getInstance().notifyObserversToPurgeActiveNetworkList(activeNetIds);
    }

    // For testing, pretend a default network changed.
    @CalledByNative
    public static void fakeDefaultNetwork(long netId, int connectionType) {
        setAutoDetectConnectivityState(false);
        getInstance().notifyObserversOfConnectionTypeChange(connectionType, netId);
    }

    // For testing, pretend the max bandwidth has changed.
    @CalledByNative
    public static void fakeMaxBandwidthChanged(double maxBandwidthMbps) {
        setAutoDetectConnectivityState(false);
        getInstance().notifyObserversOfMaxBandwidthChange(maxBandwidthMbps);
    }

    private void updateCurrentConnectionType(int newConnectionType) {
        mCurrentConnectionType = newConnectionType;
        notifyObserversOfConnectionTypeChange(newConnectionType);
    }

    private void updateCurrentMaxBandwidth(double maxBandwidthMbps) {
        if (maxBandwidthMbps == mCurrentMaxBandwidth
                && mCurrentConnectionType == mMaxBandwidthConnectionType) {
            return;
        }
        mCurrentMaxBandwidth = maxBandwidthMbps;
        mMaxBandwidthConnectionType = mCurrentConnectionType;
        notifyObserversOfMaxBandwidthChange(maxBandwidthMbps);
    }

    /**
     * Alerts all observers of a connection change.
     */
    void notifyObserversOfConnectionTypeChange(int newConnectionType) {
        notifyObserversOfConnectionTypeChange(newConnectionType, getCurrentDefaultNetId());
    }

    private void notifyObserversOfConnectionTypeChange(int newConnectionType, long defaultNetId) {
        for (Long nativeChangeNotifier : mNativeChangeNotifiers) {
            nativeNotifyConnectionTypeChanged(
                    nativeChangeNotifier, newConnectionType, defaultNetId);
        }
        for (ConnectionTypeObserver observer : mConnectionTypeObservers) {
            observer.onConnectionTypeChanged(newConnectionType);
        }
    }

    /**
     * Alerts all observers of a bandwidth change.
     */
    void notifyObserversOfMaxBandwidthChange(double maxBandwidthMbps) {
        for (Long nativeChangeNotifier : mNativeChangeNotifiers) {
            nativeNotifyMaxBandwidthChanged(nativeChangeNotifier, maxBandwidthMbps);
        }
    }

    /**
     * Alerts all observers of a network connect.
     */
    void notifyObserversOfNetworkConnect(long netId, int connectionType) {
        for (Long nativeChangeNotifier : mNativeChangeNotifiers) {
            nativeNotifyOfNetworkConnect(nativeChangeNotifier, netId, connectionType);
        }
    }

    /**
     * Alerts all observers of a network soon to be disconnected.
     */
    void notifyObserversOfNetworkSoonToDisconnect(long netId) {
        for (Long nativeChangeNotifier : mNativeChangeNotifiers) {
            nativeNotifyOfNetworkSoonToDisconnect(nativeChangeNotifier, netId);
        }
    }

    /**
     * Alerts all observers of a network disconnect.
     */
    void notifyObserversOfNetworkDisconnect(long netId) {
        for (Long nativeChangeNotifier : mNativeChangeNotifiers) {
            nativeNotifyOfNetworkDisconnect(nativeChangeNotifier, netId);
        }
    }

    /**
     * Alerts all observers to purge cached lists of active networks, of any
     * networks not in the accompanying list of active networks. This is
     * issued if a period elapsed where disconnected notifications may have
     * been missed, and acts to keep cached lists of active networks accurate.
     */
    void notifyObserversToPurgeActiveNetworkList(long[] activeNetIds) {
        for (Long nativeChangeNotifier : mNativeChangeNotifiers) {
            nativeNotifyPurgeActiveNetworkList(nativeChangeNotifier, activeNetIds);
        }
    }

    /**
     * Adds an observer for any connection type changes.
     */
    public static void addConnectionTypeObserver(ConnectionTypeObserver observer) {
        getInstance().addConnectionTypeObserverInternal(observer);
    }

    private void addConnectionTypeObserverInternal(ConnectionTypeObserver observer) {
        mConnectionTypeObservers.addObserver(observer);
    }

    /**
     * Removes an observer for any connection type changes.
     */
    public static void removeConnectionTypeObserver(ConnectionTypeObserver observer) {
        getInstance().removeConnectionTypeObserverInternal(observer);
    }

    private void removeConnectionTypeObserverInternal(ConnectionTypeObserver observer) {
        mConnectionTypeObservers.removeObserver(observer);
    }

    @NativeClassQualifiedName("NetworkChangeNotifierDelegateAndroid")
    private native void nativeNotifyConnectionTypeChanged(
            long nativePtr, int newConnectionType, long defaultNetId);

    @NativeClassQualifiedName("NetworkChangeNotifierDelegateAndroid")
    private native void nativeNotifyMaxBandwidthChanged(long nativePtr, double maxBandwidthMbps);

    @NativeClassQualifiedName("NetworkChangeNotifierDelegateAndroid")
    private native void nativeNotifyOfNetworkConnect(
            long nativePtr, long netId, int connectionType);

    @NativeClassQualifiedName("NetworkChangeNotifierDelegateAndroid")
    private native void nativeNotifyOfNetworkSoonToDisconnect(long nativePtr, long netId);

    @NativeClassQualifiedName("NetworkChangeNotifierDelegateAndroid")
    private native void nativeNotifyOfNetworkDisconnect(long nativePtr, long netId);

    @NativeClassQualifiedName("NetworkChangeNotifierDelegateAndroid")
    private native void nativeNotifyPurgeActiveNetworkList(long nativePtr, long[] activeNetIds);

    private static native double nativeGetMaxBandwidthForConnectionSubtype(int subtype);

    // For testing only.
    public static NetworkChangeNotifierAutoDetect getAutoDetectorForTest() {
        return getInstance().mAutoDetector;
    }

    /**
     * Checks if there currently is connectivity.
     */
    public static boolean isOnline() {
        int connectionType = getInstance().getCurrentConnectionType();
        return connectionType != ConnectionType.CONNECTION_NONE;
    }
}
