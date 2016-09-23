// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test;

import android.app.Activity;
import android.test.ActivityInstrumentationTestCase2;

import org.chromium.base.test.util.parameter.BaseParameter;
import org.chromium.base.test.util.parameter.Parameter;
import org.chromium.base.test.util.parameter.Parameterizable;
import org.chromium.base.test.util.parameter.parameters.MethodParameter;

import java.util.HashMap;
import java.util.Map;

/**
 * Base class for all Activity-based Instrumentation tests.
 *
 * @param <T> The Activity type.
 */
public class BaseActivityInstrumentationTestCase<T extends Activity>
        extends ActivityInstrumentationTestCase2<T> implements Parameterizable {
    private Parameter.Reader mParameterReader;
    private Map<String, BaseParameter> mAvailableParameters;

    /**
     * Creates a instance for running tests against an Activity of the given class.
     *
     * @param activityClass The type of activity that will be tested.
     */
    public BaseActivityInstrumentationTestCase(Class<T> activityClass) {
        super(activityClass);
    }

    /**
     * Creates the {@link Map} of available parameters for the test to use.
     *
     * @return a {@link Map} of {@link BaseParameter} objects.
     */
    protected Map<String, BaseParameter> createAvailableParameters() {
        Map<String, BaseParameter> availableParameters = new HashMap<>();
        availableParameters
                .put(MethodParameter.PARAMETER_TAG, new MethodParameter(getParameterReader()));
        return availableParameters;
    }

    /**
     * Gets the {@link Map} of available parameters that inherited classes can use.
     *
     * @return a {@link Map} of {@link BaseParameter} objects to set as the available parameters.
     */
    public Map<String, BaseParameter> getAvailableParameters() {
        return mAvailableParameters;
    }

    /**
     * Gets a specific parameter from the current test.
     *
     * @param parameterTag a string with the name of the {@link BaseParameter} we want.
     * @return a parameter that extends {@link BaseParameter} that has the matching parameterTag.
     */
    @SuppressWarnings("unchecked")
    public <T extends BaseParameter> T getAvailableParameter(String parameterTag) {
        return (T) mAvailableParameters.get(parameterTag);
    }

    /**
     * Setter method for {@link Parameter.Reader}.
     *
     * @param parameterReader the {@link Parameter.Reader} to set.
     */
    public void setParameterReader(Parameter.Reader parameterReader) {
        mParameterReader = parameterReader;
        mAvailableParameters = createAvailableParameters();
    }

    /**
     * Getter method for {@link Parameter.Reader} object to be used by test cases reading the
     * parameter.
     *
     * @return the {@link Parameter.Reader} for the current {@link
     * org.chromium.base.test.util.parameter.ParameterizedTest} being run.
     */
    protected Parameter.Reader getParameterReader() {
        return mParameterReader;
    }
}
