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
     *         128 characters as this is used for crash and UMA reporting, which should avoid huge
     *         strings.
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
    public static String getGMSVersionCode(Context context) {
        String msg = "gms versionCode not available.";
        try {
            PackageManager packageManager = context.getPackageManager();
            PackageInfo packageInfo = packageManager.getPackageInfo("com.google.android.gms", 0);
            msg = Integer.toString(packageInfo.versionCode);
        } catch (NameNotFoundException e) {
            Log.d(TAG, "GMS package is not found.", e);
        }
        return msg;
    }

    @CalledByNative
    public static String getPackageVersionCode(Context context) {
        String msg = "versionCode not available.";
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(context.getPackageName(), 0);
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
    public static String getPackageVersionName(Context context) {
        String msg = "versionName not available";
        try {
            PackageManager pm = context.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(context.getPackageName(), 0);
            msg = "";
            if (pi.versionName != null) {
                msg = pi.versionName;
            }
        } catch (NameNotFoundException e) {
            Log.d(TAG, msg);
        }
        return msg;
    }

    @CalledByNative
    public static String getPackageLabel(Context context) {
        // Third-party code does disk read on the getApplicationInfo call. http://crbug.com/614343
        StrictMode.ThreadPolicy oldPolicy = StrictMode.allowThreadDiskReads();
        try {
            PackageManager packageManager = context.getPackageManager();
            ApplicationInfo appInfo = packageManager.getApplicationInfo(context.getPackageName(),
                    PackageManager.GET_META_DATA);
            CharSequence label = packageManager.getApplicationLabel(appInfo);
            return  label != null ? label.toString() : "";
        } catch (NameNotFoundException e) {
            return "";
        } finally {
            StrictMode.setThreadPolicy(oldPolicy);
        }
    }

    @CalledByNative
    public static String getPackageName(Context context) {
        String packageName = context != null ? context.getPackageName() : null;
        return packageName != null ? packageName : "";
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
     * @return Whether the current build version is greater than Android N.
     */
    public static boolean isGreaterThanN() {
        return Build.VERSION.SDK_INT > 24 || Build.VERSION.CODENAME.equals("NMR1");
    }

    /**
     * @return Whether the current device is running Android O release or newer.
     */
    public static boolean isAtLeastO() {
        return !"REL".equals(Build.VERSION.CODENAME)
                && ("O".equals(Build.VERSION.CODENAME) || Build.VERSION.CODENAME.startsWith("OMR"));
    }
}
