// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net;

import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
import static android.net.NetworkCapabilities.TRANSPORT_CELLULAR;
import static android.net.NetworkCapabilities.TRANSPORT_VPN;
import static android.net.NetworkCapabilities.TRANSPORT_WIFI;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.ContextWrapper;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.ConnectivityManager.NetworkCallback;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Build;
import android.support.test.filters.MediumTest;
import android.telephony.TelephonyManager;
import android.test.InstrumentationTestCase;
import android.test.UiThreadTest;

import org.chromium.base.ApplicationState;
import org.chromium.base.ThreadUtils;
import org.chromium.base.library_loader.LibraryLoader;
import org.chromium.base.library_loader.LibraryProcessType;
import org.chromium.base.test.util.Feature;
import org.chromium.net.NetworkChangeNotifierAutoDetect.ConnectivityManagerDelegate;
import org.chromium.net.NetworkChangeNotifierAutoDetect.NetworkState;
import org.chromium.net.NetworkChangeNotifierAutoDetect.WifiManagerDelegate;
import org.chromium.net.test.util.NetworkChangeNotifierTestUtil;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.FutureTask;

/**
 * Tests for org.chromium.net.NetworkChangeNotifier.
 */
@SuppressLint("NewApi")
public class NetworkChangeNotifierTest extends InstrumentationTestCase {
    /**
     * Listens for alerts fired by the NetworkChangeNotifier when network status changes.
     */
    private static class NetworkChangeNotifierTestObserver
            implements NetworkChangeNotifier.ConnectionTypeObserver {
        private boolean mReceivedNotification = false;

        @Override
        public void onConnectionTypeChanged(int connectionType) {
            mReceivedNotification = true;
        }

        public boolean hasReceivedNotification() {
            return mReceivedNotification;
        }

        public void resetHasReceivedNotification() {
            mReceivedNotification = false;
        }
    }

    /**
      * Listens for native notifications of max bandwidth change.
      */
    private static class TestNetworkChangeNotifier extends NetworkChangeNotifier {
        private TestNetworkChangeNotifier(Context context) {
            super(context);
        }

        @Override
        void notifyObserversOfMaxBandwidthChange(double maxBandwidthMbps) {
            mReceivedMaxBandwidthNotification = true;
        }

        public boolean hasReceivedMaxBandwidthNotification() {
            return mReceivedMaxBandwidthNotification;
        }

        public void resetHasReceivedMaxBandwidthNotification() {
            mReceivedMaxBandwidthNotification = false;
        }

        private boolean mReceivedMaxBandwidthNotification = false;
    }

    private static NetworkCapabilities getCapabilities(int transport) {
        // Create a NetworkRequest with corresponding capabilities
        NetworkRequest request = new NetworkRequest.Builder()
                                         .addCapability(NET_CAPABILITY_INTERNET)
                                         .addTransportType(transport)
                                         .build();
        // Extract the NetworkCapabilities from the NetworkRequest.
        try {
            return (NetworkCapabilities) request.getClass()
                    .getDeclaredField("networkCapabilities")
                    .get(request);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            return null;
        }
    }

    private static void triggerApplicationStateChange(
            final RegistrationPolicyApplicationStatus policy, final int applicationState) {
        ThreadUtils.runOnUiThreadBlocking(new Runnable() {
            @Override
            public void run() {
                policy.onApplicationStateChange(applicationState);
            }
        });
    }

    /**
     * Mocks out calls to the ConnectivityManager.
     */
    private class MockConnectivityManagerDelegate extends ConnectivityManagerDelegate {
        // A network we're pretending is currently connected.
        private class MockNetwork {
            // Network identifier
            final int mNetId;
            // Transport, one of android.net.NetworkCapabilities.TRANSPORT_*
            final int mTransport;
            // Is this VPN accessible to the current user?
            final boolean mVpnAccessible;

            NetworkCapabilities getCapabilities() {
                return NetworkChangeNotifierTest.getCapabilities(mTransport);
            }

            /**
             * @param netId Network identifier
             * @param transport Transport, one of android.net.NetworkCapabilities.TRANSPORT_*
             * @param vpnAccessible Is this VPN accessible to the current user?
             */
            MockNetwork(int netId, int transport, boolean vpnAccessible) {
                mNetId = netId;
                mTransport = transport;
                mVpnAccessible = vpnAccessible;
            }
        }

        // List of networks we're pretending are currently connected.
        private final ArrayList<MockNetwork> mMockNetworks = new ArrayList<>();

        private boolean mActiveNetworkExists;
        private int mNetworkType;
        private int mNetworkSubtype;
        private NetworkCallback mLastRegisteredNetworkCallback;

        @Override
        public NetworkState getNetworkState(WifiManagerDelegate wifiManagerDelegate) {
            return new NetworkState(mActiveNetworkExists, mNetworkType, mNetworkSubtype,
                    mNetworkType == ConnectivityManager.TYPE_WIFI
                            ? wifiManagerDelegate.getWifiSsid()
                            : null);
        }

        @Override
        protected NetworkCapabilities getNetworkCapabilities(Network network) {
            int netId = demungeNetId(NetworkChangeNotifierAutoDetect.networkToNetId(network));
            for (MockNetwork mockNetwork : mMockNetworks) {
                if (netId == mockNetwork.mNetId) {
                    return mockNetwork.getCapabilities();
                }
            }
            return null;
        }

        @Override
        protected boolean vpnAccessible(Network network) {
            int netId = demungeNetId(NetworkChangeNotifierAutoDetect.networkToNetId(network));
            for (MockNetwork mockNetwork : mMockNetworks) {
                if (netId == mockNetwork.mNetId) {
                    return mockNetwork.mVpnAccessible;
                }
            }
            return false;
        }

        @Override
        protected Network[] getAllNetworksUnfiltered() {
            Network[] networks = new Network[mMockNetworks.size()];
            for (int i = 0; i < networks.length; i++) {
                networks[i] = netIdToNetwork(mMockNetworks.get(i).mNetId);
            }
            return networks;
        }

        // Dummy implementations to avoid NullPointerExceptions in default implementations:

        @Override
        public long getDefaultNetId() {
            return NetId.INVALID;
        }

        @Override
        public int getConnectionType(Network network) {
            return ConnectionType.CONNECTION_NONE;
        }

        @Override
        public void unregisterNetworkCallback(NetworkCallback networkCallback) {}

        // Dummy implementation that also records the last registered callback.
        @Override
        public void registerNetworkCallback(
                NetworkRequest networkRequest, NetworkCallback networkCallback) {
            mLastRegisteredNetworkCallback = networkCallback;
        }

        public void setActiveNetworkExists(boolean networkExists) {
            mActiveNetworkExists = networkExists;
        }

        public void setNetworkType(int networkType) {
            mNetworkType = networkType;
        }

        public void setNetworkSubtype(int networkSubtype) {
            mNetworkSubtype = networkSubtype;
        }

        public NetworkCallback getLastRegisteredNetworkCallback() {
            return mLastRegisteredNetworkCallback;
        }

        /**
         * Pretends a network connects.
         * @param netId Network identifier
         * @param transport Transport, one of android.net.NetworkCapabilities.TRANSPORT_*
         * @param vpnAccessible Is this VPN accessible to the current user?
         */
        public void addNetwork(int netId, int transport, boolean vpnAccessible) {
            mMockNetworks.add(new MockNetwork(netId, transport, vpnAccessible));
            mLastRegisteredNetworkCallback.onAvailable(netIdToNetwork(netId));
        }

        /**
         * Pretends a network disconnects.
         * @param netId Network identifier
         */
        public void removeNetwork(int netId) {
            for (MockNetwork mockNetwork : mMockNetworks) {
                if (mockNetwork.mNetId == netId) {
                    mMockNetworks.remove(mockNetwork);
                    mLastRegisteredNetworkCallback.onLost(netIdToNetwork(netId));
                    break;
                }
            }
        }
    }

    /**
     * Mocks out calls to the WifiManager.
     */
    private static class MockWifiManagerDelegate extends WifiManagerDelegate {
        private String mWifiSSID;

        @Override
        public String getWifiSsid() {
            return mWifiSSID;
        }

        public void setWifiSSID(String wifiSSID) {
            mWifiSSID = wifiSSID;
        }
    }

    private static int demungeNetId(long netId) {
        // On Marshmallow, demunge the NetID to undo munging done in Network.getNetworkHandle().
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            netId >>= 32;
        }
        // Now that the NetID has been demunged it is a true NetID which means it's only a 16-bit
        // value (see ConnectivityService.MAX_NET_ID) so it should be safe to cast to int.
        return (int) netId;
    }

    // Types of network changes. Each is associated with a NetworkChangeNotifierAutoDetect.Observer
    // callback, and NONE is provided to indicate no callback observed.
    private static enum ChangeType { NONE, CONNECT, SOON_TO_DISCONNECT, DISCONNECT, PURGE_LIST }

    // Recorded information about a network change that took place.
    private static class ChangeInfo {
        // The type of change.
        final ChangeType mChangeType;
        // The network identifier of the network changing.
        final int mNetId;

        /**
         * @param changeType the type of change.
         * @param netId the network identifier of the network changing.
         */
        ChangeInfo(ChangeType changeType, long netId) {
            mChangeType = changeType;
            mNetId = demungeNetId(netId);
        }
    }

    // NetworkChangeNotifierAutoDetect.Observer used to verify proper notifications are sent out.
    // Notifications come back on UI thread. assertLastChange() called on test thread.
    private static class TestNetworkChangeNotifierAutoDetectObserver
            implements NetworkChangeNotifierAutoDetect.Observer {
        // The list of network changes that have been witnessed.
        final ArrayList<ChangeInfo> mChanges = new ArrayList<>();

        @Override
        public void onConnectionTypeChanged(int newConnectionType) {}
        @Override
        public void onMaxBandwidthChanged(double maxBandwidthMbps) {}

        @Override
        public void onNetworkConnect(long netId, int connectionType) {
            ThreadUtils.assertOnUiThread();
            mChanges.add(new ChangeInfo(ChangeType.CONNECT, netId));
        }

        @Override
        public void onNetworkSoonToDisconnect(long netId) {
            ThreadUtils.assertOnUiThread();
            mChanges.add(new ChangeInfo(ChangeType.SOON_TO_DISCONNECT, netId));
        }

        @Override
        public void onNetworkDisconnect(long netId) {
            ThreadUtils.assertOnUiThread();
            mChanges.add(new ChangeInfo(ChangeType.DISCONNECT, netId));
        }

        @Override
        public void purgeActiveNetworkList(long[] activeNetIds) {
            ThreadUtils.assertOnUiThread();
            if (activeNetIds.length == 1) {
                mChanges.add(new ChangeInfo(ChangeType.PURGE_LIST, activeNetIds[0]));
            } else {
                mChanges.add(new ChangeInfo(ChangeType.PURGE_LIST, NetId.INVALID));
            }
        }

        // Verify last notification was the expected one.
        public void assertLastChange(ChangeType type, int netId) throws Exception {
            // Make sure notification processed.
            NetworkChangeNotifierTestUtil.flushUiThreadTaskQueue();
            assertNotNull(mChanges.get(0));
            assertEquals(type, mChanges.get(0).mChangeType);
            assertEquals(netId, mChanges.get(0).mNetId);
            mChanges.clear();
        }
    }

    // Network.Network(int netId) pointer.
    private TestNetworkChangeNotifier mNotifier;
    private Constructor<Network> mNetworkConstructor;
    private NetworkChangeNotifierAutoDetect mReceiver;
    private MockConnectivityManagerDelegate mConnectivityDelegate;
    private MockWifiManagerDelegate mWifiDelegate;

    private static enum WatchForChanges {
        ALWAYS,
        ONLY_WHEN_APP_IN_FOREGROUND,
    }

    /**
     * Helper method to create a notifier and delegates for testing.
     * @param watchForChanges indicates whether app wants to watch for changes always or only when
     *            it is in the foreground.
     */
    private void createTestNotifier(WatchForChanges watchForChanges) {
        Context context = new ContextWrapper(getInstrumentation().getTargetContext()) {
            // Mock out to avoid unintended system interaction.
            @Override
            public Intent registerReceiver(BroadcastReceiver receiver, IntentFilter filter) {
                return null;
            }

            @Override
            public void unregisterReceiver(BroadcastReceiver receiver) {}

            // Don't allow escaping the mock via the application context.
            @Override
            public Context getApplicationContext() {
                return this;
            }
        };
        mNotifier = new TestNetworkChangeNotifier(context);
        NetworkChangeNotifier.resetInstanceForTests(mNotifier);
        if (watchForChanges == WatchForChanges.ALWAYS) {
            NetworkChangeNotifier.registerToReceiveNotificationsAlways();
        } else {
            NetworkChangeNotifier.setAutoDetectConnectivityState(true);
        }
        mReceiver = NetworkChangeNotifier.getAutoDetectorForTest();
        assertNotNull(mReceiver);

        mConnectivityDelegate =
                new MockConnectivityManagerDelegate();
        mConnectivityDelegate.setActiveNetworkExists(true);
        mReceiver.setConnectivityManagerDelegateForTests(mConnectivityDelegate);

        mWifiDelegate = new MockWifiManagerDelegate();
        mReceiver.setWifiManagerDelegateForTests(mWifiDelegate);
        mWifiDelegate.setWifiSSID("foo");
    }

    private double getCurrentMaxBandwidthInMbps() {
        final NetworkChangeNotifierAutoDetect.NetworkState networkState =
                mReceiver.getCurrentNetworkState();
        return mReceiver.getCurrentMaxBandwidthInMbps(networkState);
    }

    private int getCurrentConnectionType() {
        final NetworkChangeNotifierAutoDetect.NetworkState networkState =
                mReceiver.getCurrentNetworkState();
        return NetworkChangeNotifierAutoDetect.convertToConnectionType(networkState);
    }

    // Create Network object given a NetID.
    private Network netIdToNetwork(int netId) {
        try {
            return mNetworkConstructor.newInstance(netId);
        } catch (InstantiationException | InvocationTargetException | IllegalAccessException e) {
            throw new IllegalStateException("Trying to create Network when not allowed");
        }
    }

    @Override
    protected void setUp() throws Exception {
        super.setUp();
        LibraryLoader.get(LibraryProcessType.PROCESS_BROWSER).ensureInitialized();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            // Find Network.Network(int netId) using reflection.
            mNetworkConstructor = Network.class.getConstructor(Integer.TYPE);
        }
        ThreadUtils.postOnUiThread(new Runnable() {
            @Override
            public void run() {
                createTestNotifier(WatchForChanges.ONLY_WHEN_APP_IN_FOREGROUND);
            }
        });
    }

    /**
     * Tests that the receiver registers for connectivity
     * broadcasts during construction when the registration policy dictates.
     */
    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkChangeNotifierRegistersWhenPolicyDictates()
            throws InterruptedException {
        Context context = getInstrumentation().getTargetContext();

        NetworkChangeNotifierAutoDetect.Observer observer =
                new TestNetworkChangeNotifierAutoDetectObserver();

        NetworkChangeNotifierAutoDetect receiver = new NetworkChangeNotifierAutoDetect(
                observer, context, new RegistrationPolicyApplicationStatus() {
                    @Override
                    int getApplicationState() {
                        return ApplicationState.HAS_RUNNING_ACTIVITIES;
                    }
                });

        assertTrue(receiver.isReceiverRegisteredForTesting());

        receiver = new NetworkChangeNotifierAutoDetect(
                observer, context, new RegistrationPolicyApplicationStatus() {
                    @Override
                    int getApplicationState() {
                        return ApplicationState.HAS_PAUSED_ACTIVITIES;
                    }
                });

        assertFalse(receiver.isReceiverRegisteredForTesting());
    }

    /**
     * Tests that the receiver toggles registration for connectivity intents based on activity
     * state.
     */
    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkChangeNotifierRegistersForIntents() throws InterruptedException {
        RegistrationPolicyApplicationStatus policy =
                (RegistrationPolicyApplicationStatus) mReceiver.getRegistrationPolicy();
        triggerApplicationStateChange(policy, ApplicationState.HAS_RUNNING_ACTIVITIES);
        assertTrue(mReceiver.isReceiverRegisteredForTesting());

        triggerApplicationStateChange(policy, ApplicationState.HAS_PAUSED_ACTIVITIES);
        assertFalse(mReceiver.isReceiverRegisteredForTesting());

        triggerApplicationStateChange(policy, ApplicationState.HAS_RUNNING_ACTIVITIES);
        assertTrue(mReceiver.isReceiverRegisteredForTesting());
    }

    /**
     * Tests that changing the network type changes the maxBandwidth.
     */
    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkChangeNotifierMaxBandwidthEthernet() throws InterruptedException {
        // Show that for Ethernet the link speed is unknown (+Infinity).
        mConnectivityDelegate.setNetworkType(ConnectivityManager.TYPE_ETHERNET);
        assertEquals(ConnectionType.CONNECTION_ETHERNET, getCurrentConnectionType());
        assertEquals(Double.POSITIVE_INFINITY, getCurrentMaxBandwidthInMbps());
    }

    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkChangeNotifierMaxBandwidthWifi() throws InterruptedException {
        // Show that for WiFi the link speed is unknown (+Infinity).
        mConnectivityDelegate.setNetworkType(ConnectivityManager.TYPE_WIFI);
        assertEquals(ConnectionType.CONNECTION_WIFI, getCurrentConnectionType());
        assertEquals(Double.POSITIVE_INFINITY, getCurrentMaxBandwidthInMbps());
    }

    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkChangeNotifierMaxBandwidthWiMax() throws InterruptedException {
        // Show that for WiMax the link speed is unknown (+Infinity), although the type is 4g.
        // TODO(jkarlin): Add support for CONNECTION_WIMAX as specified in
        // http://w3c.github.io/netinfo/.
        mConnectivityDelegate.setNetworkType(ConnectivityManager.TYPE_WIMAX);
        assertEquals(ConnectionType.CONNECTION_4G, getCurrentConnectionType());
        assertEquals(Double.POSITIVE_INFINITY, getCurrentMaxBandwidthInMbps());
    }

    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkChangeNotifierMaxBandwidthBluetooth() throws InterruptedException {
        // Show that for bluetooth the link speed is unknown (+Infinity).
        mConnectivityDelegate.setNetworkType(ConnectivityManager.TYPE_BLUETOOTH);
        assertEquals(ConnectionType.CONNECTION_BLUETOOTH, getCurrentConnectionType());
        assertEquals(Double.POSITIVE_INFINITY, getCurrentMaxBandwidthInMbps());
    }

    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkChangeNotifierMaxBandwidthMobile() throws InterruptedException {
        // Test that for mobile types the subtype is used to determine the maxBandwidth.
        mConnectivityDelegate.setNetworkType(ConnectivityManager.TYPE_MOBILE);
        mConnectivityDelegate.setNetworkSubtype(TelephonyManager.NETWORK_TYPE_LTE);
        assertEquals(ConnectionType.CONNECTION_4G, getCurrentConnectionType());
        assertEquals(100.0, getCurrentMaxBandwidthInMbps());
    }

    /**
     * Tests that when Chrome gets an intent indicating a change in network connectivity, it sends a
     * notification to Java observers.
     */
    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkChangeNotifierJavaObservers() throws InterruptedException {
        // Initialize the NetworkChangeNotifier with a connection.
        Intent connectivityIntent = new Intent(ConnectivityManager.CONNECTIVITY_ACTION);
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);

        // We shouldn't be re-notified if the connection hasn't actually changed.
        NetworkChangeNotifierTestObserver observer = new NetworkChangeNotifierTestObserver();
        NetworkChangeNotifier.addConnectionTypeObserver(observer);
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);
        assertFalse(observer.hasReceivedNotification());

        // We shouldn't be notified if we're connected to non-Wifi and the Wifi SSID changes.
        mWifiDelegate.setWifiSSID("bar");
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);
        assertFalse(observer.hasReceivedNotification());
        // We should be notified when we change to Wifi.
        mConnectivityDelegate.setNetworkType(ConnectivityManager.TYPE_WIFI);
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);
        assertTrue(observer.hasReceivedNotification());
        observer.resetHasReceivedNotification();
        // We should be notified when the Wifi SSID changes.
        mWifiDelegate.setWifiSSID("foo");
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);
        assertTrue(observer.hasReceivedNotification());
        observer.resetHasReceivedNotification();
        // We shouldn't be re-notified if the Wifi SSID hasn't actually changed.
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);
        assertFalse(observer.hasReceivedNotification());

        // Mimic that connectivity has been lost and ensure that Chrome notifies our observer.
        mConnectivityDelegate.setActiveNetworkExists(false);
        Intent noConnectivityIntent = new Intent(ConnectivityManager.CONNECTIVITY_ACTION);
        mReceiver.onReceive(getInstrumentation().getTargetContext(), noConnectivityIntent);
        assertTrue(observer.hasReceivedNotification());

        observer.resetHasReceivedNotification();
        // Pretend we got moved to the background.
        final RegistrationPolicyApplicationStatus policy =
                (RegistrationPolicyApplicationStatus) mReceiver.getRegistrationPolicy();
        triggerApplicationStateChange(policy, ApplicationState.HAS_PAUSED_ACTIVITIES);
        // Change the state.
        mConnectivityDelegate.setActiveNetworkExists(true);
        mConnectivityDelegate.setNetworkType(ConnectivityManager.TYPE_WIFI);
        // The NetworkChangeNotifierAutoDetect doesn't receive any notification while we are in the
        // background, but when we get back to the foreground the state changed should be detected
        // and a notification sent.
        triggerApplicationStateChange(policy, ApplicationState.HAS_RUNNING_ACTIVITIES);
        assertTrue(observer.hasReceivedNotification());
    }

    /**
     * Tests that when Chrome gets an intent indicating a change in max bandwidth, it sends a
     * notification to Java observers.
     */
    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkChangeNotifierMaxBandwidthNotifications() throws InterruptedException {
        // Initialize the NetworkChangeNotifier with a connection.
        mConnectivityDelegate.setActiveNetworkExists(true);
        mConnectivityDelegate.setNetworkType(ConnectivityManager.TYPE_WIFI);
        Intent connectivityIntent = new Intent(ConnectivityManager.CONNECTIVITY_ACTION);
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);
        assertTrue(mNotifier.hasReceivedMaxBandwidthNotification());
        mNotifier.resetHasReceivedMaxBandwidthNotification();

        // We shouldn't be re-notified if the connection hasn't actually changed.
        NetworkChangeNotifierTestObserver observer = new NetworkChangeNotifierTestObserver();
        NetworkChangeNotifier.addConnectionTypeObserver(observer);
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);
        assertFalse(mNotifier.hasReceivedMaxBandwidthNotification());

        // We should be notified if bandwidth and connection type changed.
        mConnectivityDelegate.setNetworkType(ConnectivityManager.TYPE_ETHERNET);
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);
        assertTrue(mNotifier.hasReceivedMaxBandwidthNotification());
        mNotifier.resetHasReceivedMaxBandwidthNotification();

        // We should be notified if the connection type changed, but not the bandwidth.
        // Note that TYPE_ETHERNET and TYPE_BLUETOOTH have the same +INFINITY max bandwidth.
        // This test will fail if that changes.
        mConnectivityDelegate.setNetworkType(ConnectivityManager.TYPE_BLUETOOTH);
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);
        assertTrue(mNotifier.hasReceivedMaxBandwidthNotification());
    }

    /**
     * Tests that when setting {@code registerToReceiveNotificationsAlways()},
     * a NetworkChangeNotifierAutoDetect object is successfully created.
     */
    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testCreateNetworkChangeNotifierAlwaysWatchForChanges() throws InterruptedException {
        createTestNotifier(WatchForChanges.ALWAYS);
        assertTrue(mReceiver.isReceiverRegisteredForTesting());

        // Make sure notifications can be received.
        NetworkChangeNotifierTestObserver observer = new NetworkChangeNotifierTestObserver();
        NetworkChangeNotifier.addConnectionTypeObserver(observer);
        Intent connectivityIntent = new Intent(ConnectivityManager.CONNECTIVITY_ACTION);
        mReceiver.onReceive(getInstrumentation().getTargetContext(), connectivityIntent);
        assertTrue(observer.hasReceivedNotification());
    }

    /**
     * Tests that ConnectivityManagerDelegate doesn't crash. This test cannot rely on having any
     * active network connections so it cannot usefully check results, but it can at least check
     * that the functions don't crash.
     */
    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testConnectivityManagerDelegateDoesNotCrash() {
        ConnectivityManagerDelegate delegate =
                new ConnectivityManagerDelegate(getInstrumentation().getTargetContext());
        delegate.getNetworkState(new WifiManagerDelegate(getInstrumentation().getTargetContext()));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            // getConnectionType(Network) doesn't crash upon invalid Network argument.
            Network invalidNetwork = netIdToNetwork(NetId.INVALID);
            assertEquals(
                    ConnectionType.CONNECTION_NONE, delegate.getConnectionType(invalidNetwork));

            Network[] networks = delegate.getAllNetworksUnfiltered();
            if (networks.length >= 1) {
                delegate.getConnectionType(networks[0]);
            }
            delegate.getDefaultNetId();
            NetworkCallback networkCallback = new NetworkCallback();
            NetworkRequest networkRequest = new NetworkRequest.Builder().build();
            delegate.registerNetworkCallback(networkRequest, networkCallback);
            delegate.unregisterNetworkCallback(networkCallback);
        }
    }

    /**
     * Tests that NetworkChangeNotifierAutoDetect queryable APIs don't crash. This test cannot rely
     * on having any active network connections so it cannot usefully check results, but it can at
     * least check that the functions don't crash.
     */
    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testQueryableAPIsDoNotCrash() {
        NetworkChangeNotifierAutoDetect.Observer observer =
                new TestNetworkChangeNotifierAutoDetectObserver();
        NetworkChangeNotifierAutoDetect ncn = new NetworkChangeNotifierAutoDetect(observer,
                getInstrumentation().getTargetContext(), new RegistrationPolicyAlwaysRegister());
        ncn.getNetworksAndTypes();
        ncn.getDefaultNetId();
    }

    /**
     * Tests that NetworkChangeNotifierAutoDetect query-able APIs return expected
     * values from the inserted mock ConnectivityManager.
     */
    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testQueryableAPIsReturnExpectedValuesFromMockDelegate() throws Exception {
        Context context = getInstrumentation().getTargetContext();

        NetworkChangeNotifierAutoDetect.Observer observer =
                new TestNetworkChangeNotifierAutoDetectObserver();

        NetworkChangeNotifierAutoDetect ncn = new NetworkChangeNotifierAutoDetect(
                observer, context, new RegistrationPolicyApplicationStatus() {
                    @Override
                    int getApplicationState() {
                        return ApplicationState.HAS_PAUSED_ACTIVITIES;
                    }
                });

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            assertEquals(0, ncn.getNetworksAndTypes().length);
            assertEquals(NetId.INVALID, ncn.getDefaultNetId());
            return;
        }

        // Insert a mocked dummy implementation for the ConnectivityDelegate.
        ncn.setConnectivityManagerDelegateForTests(new ConnectivityManagerDelegate() {
            public final Network[] mNetworks =
                    new Network[] {netIdToNetwork(111), netIdToNetwork(333)};

            @Override
            protected Network[] getAllNetworksUnfiltered() {
                return mNetworks;
            }

            @Override
            long getDefaultNetId() {
                return Integer.parseInt(mNetworks[1].toString());
            }

            @Override
            protected NetworkCapabilities getNetworkCapabilities(Network network) {
                return getCapabilities(TRANSPORT_WIFI);
            }

            @Override
            public int getConnectionType(Network network) {
                return ConnectionType.CONNECTION_NONE;
            }
        });

        // Verify that the mock delegate connectivity manager is being used
        // by the network change notifier auto-detector.
        assertEquals(333, ncn.getDefaultNetId());

        // The api {@link NetworkChangeNotifierAutoDetect#getNetworksAndTypes()}
        // returns an array of a repeated sequence of: (NetID, ConnectionType).
        // There are 4 entries in the array, two for each network.
        assertEquals(4, ncn.getNetworksAndTypes().length);
        assertEquals(111, demungeNetId(ncn.getNetworksAndTypes()[0]));
        assertEquals(ConnectionType.CONNECTION_NONE, ncn.getNetworksAndTypes()[1]);
        assertEquals(333, demungeNetId(ncn.getNetworksAndTypes()[2]));
        assertEquals(ConnectionType.CONNECTION_NONE, ncn.getNetworksAndTypes()[3]);
    }

    /**
     * Tests that callbacks are issued to Observers when NetworkChangeNotifierAutoDetect receives
     * the right signals (via its NetworkCallback).
     */
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkCallbacks() throws Exception {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP) {
            return;
        }
        // Setup NetworkChangeNotifierAutoDetect
        final Context context = getInstrumentation().getTargetContext();
        final TestNetworkChangeNotifierAutoDetectObserver observer =
                new TestNetworkChangeNotifierAutoDetectObserver();
        Callable<NetworkChangeNotifierAutoDetect> callable =
                new Callable<NetworkChangeNotifierAutoDetect>() {
                    @Override
                    public NetworkChangeNotifierAutoDetect call() {
                        return new NetworkChangeNotifierAutoDetect(
                                observer, context, new RegistrationPolicyApplicationStatus() {
                                    // This override prevents NetworkChangeNotifierAutoDetect from
                                    // registering for events right off the bat. We'll delay this
                                    // until our MockConnectivityManagerDelegate is first installed
                                    // to prevent inadvertent communication with the real
                                    // ConnectivityManager.
                                    @Override
                                    int getApplicationState() {
                                        return ApplicationState.HAS_PAUSED_ACTIVITIES;
                                    }
                                });
                    }
                };
        FutureTask<NetworkChangeNotifierAutoDetect> task = new FutureTask<>(callable);
        ThreadUtils.postOnUiThread(task);
        NetworkChangeNotifierAutoDetect ncn = task.get();

        // Insert mock ConnectivityDelegate
        mConnectivityDelegate = new MockConnectivityManagerDelegate();
        ncn.setConnectivityManagerDelegateForTests(mConnectivityDelegate);
        // Now that mock ConnectivityDelegate is inserted, pretend app is foregrounded
        // so NetworkChangeNotifierAutoDetect will register its NetworkCallback.
        assertFalse(ncn.isReceiverRegisteredForTesting());

        RegistrationPolicyApplicationStatus policy =
                (RegistrationPolicyApplicationStatus) ncn.getRegistrationPolicy();
        triggerApplicationStateChange(policy, ApplicationState.HAS_RUNNING_ACTIVITIES);
        assertTrue(ncn.isReceiverRegisteredForTesting());

        // Find NetworkChangeNotifierAutoDetect's NetworkCallback, which should have been registered
        // with mConnectivityDelegate.
        NetworkCallback networkCallback = mConnectivityDelegate.getLastRegisteredNetworkCallback();
        assertNotNull(networkCallback);

        // First thing we'll receive is a purge to initialize any network lists.
        observer.assertLastChange(ChangeType.PURGE_LIST, NetId.INVALID);

        // Test connected signal is passed along.
        mConnectivityDelegate.addNetwork(100, TRANSPORT_WIFI, false);
        observer.assertLastChange(ChangeType.CONNECT, 100);

        // Test soon-to-be-disconnected signal is passed along.
        networkCallback.onLosing(netIdToNetwork(100), 30);
        observer.assertLastChange(ChangeType.SOON_TO_DISCONNECT, 100);

        // Test connected signal is passed along.
        mConnectivityDelegate.removeNetwork(100);
        observer.assertLastChange(ChangeType.DISCONNECT, 100);

        // Simulate app backgrounding then foregrounding.
        assertTrue(ncn.isReceiverRegisteredForTesting());
        triggerApplicationStateChange(policy, ApplicationState.HAS_PAUSED_ACTIVITIES);
        assertFalse(ncn.isReceiverRegisteredForTesting());
        triggerApplicationStateChange(policy, ApplicationState.HAS_RUNNING_ACTIVITIES);
        assertTrue(ncn.isReceiverRegisteredForTesting());
        // Verify network list purged.
        observer.assertLastChange(ChangeType.PURGE_LIST, NetId.INVALID);

        //
        // VPN testing
        //

        // Add a couple normal networks
        mConnectivityDelegate.addNetwork(100, TRANSPORT_WIFI, false);
        observer.assertLastChange(ChangeType.CONNECT, 100);
        mConnectivityDelegate.addNetwork(101, TRANSPORT_CELLULAR, false);
        observer.assertLastChange(ChangeType.CONNECT, 101);

        // Verify inaccessible VPN is ignored
        mConnectivityDelegate.addNetwork(102, TRANSPORT_VPN, false);
        NetworkChangeNotifierTestUtil.flushUiThreadTaskQueue();
        assertEquals(observer.mChanges.size(), 0);
        // The disconnect will be ignored in
        // NetworkChangeNotifierDelegateAndroid::NotifyOfNetworkDisconnect() because no
        // connect event was witnessed, but it will be sent to {@code observer}
        mConnectivityDelegate.removeNetwork(102);
        observer.assertLastChange(ChangeType.DISCONNECT, 102);

        // Verify when an accessible VPN connects, all other network disconnect
        mConnectivityDelegate.addNetwork(103, TRANSPORT_VPN, true);
        NetworkChangeNotifierTestUtil.flushUiThreadTaskQueue();
        assertEquals(2, observer.mChanges.size());
        assertEquals(ChangeType.CONNECT, observer.mChanges.get(0).mChangeType);
        assertEquals(103, observer.mChanges.get(0).mNetId);
        assertEquals(ChangeType.PURGE_LIST, observer.mChanges.get(1).mChangeType);
        assertEquals(103, observer.mChanges.get(1).mNetId);
        observer.mChanges.clear();

        // Verify when an accessible VPN disconnects, all other networks reconnect
        mConnectivityDelegate.removeNetwork(103);
        NetworkChangeNotifierTestUtil.flushUiThreadTaskQueue();
        assertEquals(3, observer.mChanges.size());
        assertEquals(ChangeType.DISCONNECT, observer.mChanges.get(0).mChangeType);
        assertEquals(103, observer.mChanges.get(0).mNetId);
        assertEquals(ChangeType.CONNECT, observer.mChanges.get(1).mChangeType);
        assertEquals(100, observer.mChanges.get(1).mNetId);
        assertEquals(ChangeType.CONNECT, observer.mChanges.get(2).mChangeType);
        assertEquals(101, observer.mChanges.get(2).mNetId);
    }

    /**
     * Tests that isOnline() returns the correct result.
     */
    @UiThreadTest
    @MediumTest
    @Feature({"Android-AppBase"})
    public void testNetworkChangeNotifierIsOnline() throws InterruptedException {
        Intent intent = new Intent(ConnectivityManager.CONNECTIVITY_ACTION);
        // For any connection type it should return true.
        for (int i = ConnectivityManager.TYPE_MOBILE; i < ConnectivityManager.TYPE_VPN; i++) {
            mConnectivityDelegate.setActiveNetworkExists(true);
            mConnectivityDelegate.setNetworkType(i);
            mReceiver.onReceive(getInstrumentation().getTargetContext(), intent);
            assertTrue(NetworkChangeNotifier.isOnline());
        }
        mConnectivityDelegate.setActiveNetworkExists(false);
        mReceiver.onReceive(getInstrumentation().getTargetContext(), intent);
        assertFalse(NetworkChangeNotifier.isOnline());
    }
}
