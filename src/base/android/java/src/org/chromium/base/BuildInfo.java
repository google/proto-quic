// Copyright 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.os.Build;

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
    private static String[] getAll() {
        try {
            String packageName = ContextUtils.getApplicationContext().getPackageName();
            PackageManager pm = ContextUtils.getApplicationContext().getPackageManager();
            PackageInfo pi = pm.getPackageInfo(packageName, 0);
            String versionCode = pi.versionCode <= 0 ? "" : Integer.toString(pi.versionCode);
            String versionName = pi.versionName == null ? "" : pi.versionName;

            CharSequence label = pm.getApplicationLabel(pi.applicationInfo);
            String packageLabel = label == null ? "" : label.toString();

            // Use lastUpdateTime when developing locally, since versionCode does not normally
            // change in this case.
            long version = pi.versionCode > 10 ? pi.versionCode : pi.lastUpdateTime;
            String extractedFileSuffix = String.format("@%s", Long.toHexString(version));

            // Do not alter this list without updating callers of it.
            return new String[] {
                    Build.BRAND, Build.DEVICE, Build.ID, Build.MANUFACTURER, Build.MODEL,
                    String.valueOf(Build.VERSION.SDK_INT), Build.TYPE, packageLabel, packageName,
                    versionCode, versionName, getAndroidBuildFingerprint(), getGMSVersionCode(pm),
                    extractedFileSuffix,
            };
        } catch (NameNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * @return The build fingerprint for the current Android install.  The value is truncated to a
     * 128 characters as this is used for crash and UMA reporting, which should avoid huge
     * strings.
     */
    private static String getAndroidBuildFingerprint() {
        return Build.FINGERPRINT.substring(
                0, Math.min(Build.FINGERPRINT.length(), MAX_FINGERPRINT_LENGTH));
    }

    private static String getGMSVersionCode(PackageManager packageManager) {
        String msg = "gms versionCode not available.";
        try {
            PackageInfo packageInfo = packageManager.getPackageInfo("com.google.android.gms", 0);
            msg = Integer.toString(packageInfo.versionCode);
        } catch (NameNotFoundException e) {
            Log.d(TAG, "GMS package is not found.", e);
        }
        return msg;
    }

    public static String getPackageVersionName() {
        return getAll()[10];
    }

    /** Returns a string that is different each time the apk changes. */
    public static String getExtractedFileSuffix() {
        return getAll()[13];
    }

    public static String getPackageLabel() {
        return getAll()[7];
    }

    public static String getPackageName() {
        return ContextUtils.getApplicationContext().getPackageName();
    }

    /**
     * Check if this is a debuggable build of Android. Use this to enable developer-only features.
     */
    public static boolean isDebugAndroid() {
        return "eng".equals(Build.TYPE) || "userdebug".equals(Build.TYPE);
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
