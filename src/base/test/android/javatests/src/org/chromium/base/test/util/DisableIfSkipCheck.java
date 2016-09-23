// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.util;

import android.os.Build;

import junit.framework.TestCase;

import org.chromium.base.Log;

import java.lang.reflect.Method;
import java.util.Arrays;

/**
 * Checks for conditional disables.
 *
 * Currently, this only includes checks against a few {@link android.os.Build} values.
 */
public class DisableIfSkipCheck extends SkipCheck {

    private static final String TAG = "cr_base_test";

    @Override
    public boolean shouldSkip(TestCase testCase) {
        Method method = getTestMethod(testCase);
        if (method == null) return true;

        for (DisableIf.Build v : getAnnotations(method, DisableIf.Build.class)) {
            if (abi(v) && hardware(v) && product(v) && sdk(v)) {
                if (!v.message().isEmpty()) {
                    Log.i(TAG, "%s is disabled: %s", testCase.toString(), v.message());
                }
                return true;
            }
        }

        for (DisableIf.Device d : getAnnotations(method, DisableIf.Device.class)) {
            for (String deviceType : d.type()) {
                if (deviceTypeApplies(deviceType)) {
                    Log.i(TAG, "Test " + testCase.getClass().getName() + "#"
                            + testCase.getName() + " disabled because of "
                            + d);
                    return true;
                }
            }
        }

        return false;
    }

    @SuppressWarnings("deprecation")
    private boolean abi(DisableIf.Build v) {
        if (v.supported_abis_includes().isEmpty()) return true;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return Arrays.asList(Build.SUPPORTED_ABIS).contains(
                    v.supported_abis_includes());
        } else {
            return Build.CPU_ABI.equals(v.supported_abis_includes())
                    || Build.CPU_ABI2.equals(v.supported_abis_includes());
        }
    }

    private boolean hardware(DisableIf.Build v) {
        return v.hardware_is().isEmpty() || Build.HARDWARE.equals(v.hardware_is());
    }

    private boolean product(DisableIf.Build v) {
        return v.product_name_includes().isEmpty()
                || Build.PRODUCT.contains(v.product_name_includes());
    }

    private boolean sdk(DisableIf.Build v) {
        return Build.VERSION.SDK_INT > v.sdk_is_greater_than()
                && Build.VERSION.SDK_INT < v.sdk_is_less_than();
    }

    protected boolean deviceTypeApplies(String type) {
        return false;
    }

}

