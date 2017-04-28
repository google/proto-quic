// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.net;

import android.Manifest;
import android.annotation.TargetApi;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Process;
import android.telephony.CellInfo;
import android.telephony.CellInfoCdma;
import android.telephony.CellInfoGsm;
import android.telephony.CellInfoLte;
import android.telephony.CellInfoWcdma;
import android.telephony.TelephonyManager;

import org.chromium.base.ContextUtils;
import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;

import java.util.Iterator;
import java.util.List;

/**
 * This class interacts with the CellInfo API provided by Android. This class is thread safe.
 */
@JNINamespace("net::android::cellular_signal_strength")
public class AndroidCellularSignalStrength {
    /**
     * @return Signal strength (in dbM) for the currently registered cellular network. Returns
     * {@link CellularSignalStrengthError#ERROR_NOT_SUPPORTED} if the signal strength is
     * unavailable or if there are multiple cellular radios on the device.
     */
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    @CalledByNative
    public static int getSignalStrengthDbm() {
        List<CellInfo> cellInfos = getRegisteredCellInfo();
        return cellInfos == null || cellInfos.size() != 1
                ? CellularSignalStrengthError.ERROR_NOT_SUPPORTED
                : getSignalStrengthDbm(cellInfos.get(0));
    }

    /**
     * @return the signal strength level (between 0 and 4, both inclusive) for the currently
     * registered cellular network with lower value indicating lower signal strength. Returns
     * {@link CellularSignalStrengthError#ERROR_NOT_SUPPORTED} if the signal strength level is
     * unavailable or if there are multiple cellular radios on the device.
     */
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    @CalledByNative
    public static int getSignalStrengthLevel() {
        List<CellInfo> cellInfos = getRegisteredCellInfo();
        return cellInfos == null || cellInfos.size() != 1
                ? CellularSignalStrengthError.ERROR_NOT_SUPPORTED
                : getSignalStrengthLevel(cellInfos.get(0));
    }

    /**
     * Returns true if the API for quering the signal strength is available.
     * {@link android.telephony#CellInfoWcdma} is only available on API Level
     * {@link Build.VERSION_CODES#JELLY_BEAN_MR2} and higher. Also verifies that appropriate
     * permissions are already available. This ensures that on Android M and higher, Chromium will
     * not request run-time permission from the user when querying for cellular signal strength.
     * TODO(tbansal): Consider using {@link TelephonyManager#getNeighboringCellInfo}
     * for earlier versions of Android.
    */
    private static boolean isAPIAvailable() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.JELLY_BEAN_MR2) return false;

        try {
            return ContextUtils.getApplicationContext().checkPermission(
                           Manifest.permission.ACCESS_COARSE_LOCATION, Process.myPid(),
                           Process.myUid())
                    == PackageManager.PERMISSION_GRANTED;
        } catch (Exception ignored) {
            // Work around certain platforms where this method sometimes throws a runtime exception.
            // See crbug.com/663360.
        }
        return false;
    }

    /**
     * Returns all observed cell information from all radios on the device including the primary
     * and neighboring cells. Returns only the information of cells that are registered to a
     * mobile network. May return {@code null}.
     */
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private static List<CellInfo> getRegisteredCellInfo() {
        if (!isAPIAvailable()) {
            return null;
        }

        TelephonyManager telephonyManager =
                (TelephonyManager) ContextUtils.getApplicationContext().getSystemService(
                        Context.TELEPHONY_SERVICE);
        if (telephonyManager == null) {
            return null;
        }

        List<CellInfo> cellInfos = telephonyManager.getAllCellInfo();
        if (cellInfos == null) {
            return null;
        }

        Iterator<CellInfo> iter = cellInfos.iterator();
        while (iter.hasNext()) {
            if (!iter.next().isRegistered()) {
                iter.remove();
            }
        }
        return cellInfos;
    }

    /**
     * @return Signal strength (in dbM) from {@link cellInfo}. Returns {@link
     * CellularSignalStrengthError#ERROR_NOT_SUPPORTED} if the signal strength is unavailable.
     */
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private static int getSignalStrengthDbm(CellInfo cellInfo) {
        if (cellInfo instanceof CellInfoCdma) {
            return ((CellInfoCdma) cellInfo).getCellSignalStrength().getDbm();
        }
        if (cellInfo instanceof CellInfoGsm) {
            return ((CellInfoGsm) cellInfo).getCellSignalStrength().getDbm();
        }
        if (cellInfo instanceof CellInfoLte) {
            return ((CellInfoLte) cellInfo).getCellSignalStrength().getDbm();
        }
        if (cellInfo instanceof CellInfoWcdma) {
            return ((CellInfoWcdma) cellInfo).getCellSignalStrength().getDbm();
        }
        return CellularSignalStrengthError.ERROR_NOT_SUPPORTED;
    }

    /**
     * @return the signal level from {@link cellInfo}. Returns {@link
     * CellularSignalStrengthError#ERROR_NOT_SUPPORTED} if the signal
     * level is unavailable with lower value indicating lower signal strength.
     */
    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    private static int getSignalStrengthLevel(CellInfo cellInfo) {
        if (cellInfo instanceof CellInfoCdma) {
            return ((CellInfoCdma) cellInfo).getCellSignalStrength().getLevel();
        }
        if (cellInfo instanceof CellInfoGsm) {
            return ((CellInfoGsm) cellInfo).getCellSignalStrength().getLevel();
        }
        if (cellInfo instanceof CellInfoLte) {
            return ((CellInfoLte) cellInfo).getCellSignalStrength().getLevel();
        }
        if (cellInfo instanceof CellInfoWcdma) {
            return ((CellInfoWcdma) cellInfo).getCellSignalStrength().getLevel();
        }
        return CellularSignalStrengthError.ERROR_NOT_SUPPORTED;
    }
}
