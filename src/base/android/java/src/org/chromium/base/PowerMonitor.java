// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Handler;
import android.os.Looper;

import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;


/**
 * Integrates native PowerMonitor with the java side.
 */
@JNINamespace("base::android")
public class PowerMonitor  {
    private static class LazyHolder {
        private static final PowerMonitor INSTANCE = new PowerMonitor();
    }
    private static PowerMonitor sInstance;

    private boolean mIsBatteryPower;
    private final Handler mHandler = new Handler(Looper.getMainLooper());

    public static void createForTests(Context context) {
        // Applications will create this once the JNI side has been fully wired up both sides. For
        // tests, we just need native -> java, that is, we don't need to notify java -> native on
        // creation.
        sInstance = LazyHolder.INSTANCE;
    }

    /**
     * Create a PowerMonitor instance if none exists.
     * @param context The context to register broadcast receivers for.  The application context
     *                will be used from this parameter.
     */
    public static void create(Context context) {
        context = context.getApplicationContext();
        if (sInstance == null) {
            sInstance = LazyHolder.INSTANCE;
            IntentFilter ifilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent batteryStatusIntent = context.registerReceiver(null, ifilter);
            if (batteryStatusIntent != null) onBatteryChargingChanged(batteryStatusIntent);
        }
    }

    private PowerMonitor() {
    }

    public static void onBatteryChargingChanged(Intent intent) {
        if (sInstance == null) {
            // We may be called by the framework intent-filter before being fully initialized. This
            // is not a problem, since our constructor will check for the state later on.
            return;
        }
        int chargePlug = intent.getIntExtra(BatteryManager.EXTRA_PLUGGED, -1);
        // If we're not plugged, assume we're running on battery power.
        sInstance.mIsBatteryPower = chargePlug != BatteryManager.BATTERY_PLUGGED_USB
                && chargePlug != BatteryManager.BATTERY_PLUGGED_AC;
        nativeOnBatteryChargingChanged();
    }

    @CalledByNative
    private static boolean isBatteryPower() {
        return sInstance.mIsBatteryPower;
    }

    private static native void nativeOnBatteryChargingChanged();
}
