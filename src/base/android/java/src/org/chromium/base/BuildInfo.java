// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Build;
import android.os.StrictMode;

import org.chromium.base.annotations.CalledByNative;

/**
 * BuildInfo is a utility class providing easy access to {@link PackageInfo} information. This is
 * primarily of use for accessing package information from native code.
 */
public class BuildInfo {
    private static final String TAG = "BuildInfo";
    private static final int MAX_FINGERPRINT_LENGTH = 128;

    /**
     * BuildInfo is a static utility class and therefore shouldn't be instantiated.
     */
    private BuildInfo() {}

    @CalledByNative
    public static String getDevice() {
        return Build.DEVICE;
    }

    @CalledByNative
    public static String getBrand() {
        return Build.BRAND;
    }

    @CalledByNative
    public static String getAndroidBuildId() {
        return Build.ID;
    }

    /**
     * @return The build fingerprint for the current Android install.  The value is truncated to a
     * 128 characters as this is used for crash and UMA reporting, which should avoid huge
     * strings.
     */
    @CalledByNative
    public static String getAndroidBuildFingerprint() {
        return Build.FINGERPRINT.substring(
                0, Math.min(Build.FINGERPRINT.length(), MAX_FINGERPRINT_LENGTH));
    }

    @CalledByNative
    public static String getDeviceManufacturer() {
        return Build.MANUFACTURER;
    }

    @CalledByNative
    public static String getDeviceModel() {
        return Build.MODEL;
    }

    @CalledByNative
    public static String getGMSVersionCode() {
        String msg = "gms versionCode not available.";
        try {
            PackageManager packageManager =
                    ContextUtils.getApplicationContext().getPackageManager();
            PackageInfo packageInfo = packageManager.getPackageInfo("com.google.android.gms", 0);
            msg = Integer.toString(packageInfo.versionCode);
        } catch (NameNotFoundException e) {
            Log.d(TAG, "GMS package is not found.", e);
        }
        return msg;
    }

    @CalledByNative
    public static String getPackageVersionCode() {
        String msg = "versionCode not available.";
        try {
            PackageManager pm = ContextUtils.getApplicationContext().getPackageManager();
            PackageInfo pi = pm.getPackageInfo(getPackageName(), 0);
            msg = "";
            if (pi.versionCode > 0) {
                msg = Integer.toString(pi.versionCode);
            }
        } catch (NameNotFoundException e) {
            Log.d(TAG, msg);
        }
        return msg;
    }

    @CalledByNative
    public static String getPackageVersionName() {
        String msg = "versionName not available";
        try {
            PackageManager pm = ContextUtils.getApplicationContext().getPackageManager();
            PackageInfo pi = pm.getPackageInfo(getPackageName(), 0);
            msg = "";
            if (pi.versionName != null) {
                msg = pi.versionName;
            }
        } catch (NameNotFoundException e) {
            Log.d(TAG, msg);
        }
        return msg;
    }

    /** Returns a string that is different each time the apk changes. */
    @CalledByNative
    public static String getExtractedFileSuffix() {
        PackageManager pm = ContextUtils.getApplicationContext().getPackageManager();
        try {
            PackageInfo pi =
                    pm.getPackageInfo(ContextUtils.getApplicationContext().getPackageName(), 0);
            // Use lastUpdateTime when developing locally, since versionCode does not normally
            // change in this case.
            long version = pi.versionCode > 10 ? pi.versionCode : pi.lastUpdateTime;
            return "@" + Long.toHexString(version);
        } catch (PackageManager.NameNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    @CalledByNative
    public static String getPackageLabel() {
        // Third-party code does disk read on the getApplicationInfo call. http://crbug.com/614343
        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
        try {
            PackageManager packageManager =
                    ContextUtils.getApplicationContext().getPackageManager();
            ApplicationInfo appInfo = packageManager.getApplicationInfo(
                    getPackageName(), PackageManager.GET_META_DATA);
            CharSequence label = packageManager.getApplicationLabel(appInfo);
            return label != null ? label.toString() : "";
        } catch (NameNotFoundException e) {
            return "";
        } finally {
            StrictMode.setThreadPolicy(oldPolicy);
        }
    }

    @CalledByNative
    public static String getPackageName() {
        if (ContextUtils.getApplicationContext() == null) {
            return "";
        }
        return ContextUtils.getApplicationContext().getPackageName();
    }

    @CalledByNative
    public static String getBuildType() {
        return Build.TYPE;
    }

    /**
     * Check if this is a debuggable build of Android. Use this to enable developer-only features.
     */
    public static boolean isDebugAndroid() {
        return "eng".equals(Build.TYPE) || "userdebug".equals(Build.TYPE);
    }

    @CalledByNative
    public static int getSdkInt() {
        return Build.VERSION.SDK_INT;
    }

    /**
     * @return Whether the current device is running Android O release or newer.
     */
    public static boolean isAtLeastO() {
        return Build.VERSION.SDK_INT >= 26;
    }

    /**
     * @return Whether the current app targets the SDK for at least O
     */
    public static boolean targetsAtLeastO(Context appContext) {
        return appContext.getApplicationInfo().targetSdkVersion >= 26;
    }
}
