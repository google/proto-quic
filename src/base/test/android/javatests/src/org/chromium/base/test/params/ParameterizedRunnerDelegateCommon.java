// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.params;

import org.junit.runners.model.FrameworkMethod;

import java.util.List;

/**
 * Parameterized runner delegate common that implements method that needed to be
 * delegated for parameterization purposes
 */
public final class ParameterizedRunnerDelegateCommon {
    private final List<FrameworkMethod> mParameterizedFrameworkMethodList;
    private final Object mTest;

    public ParameterizedRunnerDelegateCommon(
            Object test, List<FrameworkMethod> parameterizedFrameworkMethods) {
        mTest = test;
        mParameterizedFrameworkMethodList = parameterizedFrameworkMethods;
    }

    /**
     * Do not do any validation here because running the default class runner's
     * collectInitializationErrors fail due to the overridden computeTestMethod relying on a local
     * member variable
     *
     * The validation needed for parameterized tests is already done by ParameterizedRunner.
     */
    public static void collectInitializationErrors(
            @SuppressWarnings("unused") List<Throwable> errors) {}

    public List<FrameworkMethod> computeTestMethods() {
        return mParameterizedFrameworkMethodList;
    }

    public Object createTest() {
        return mTest;
    }
}
