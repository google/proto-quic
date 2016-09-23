// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.util.parameter;

import java.util.Map;

/**
 * An interface to implement on test cases to run {@link ParameterizedTest}s.
 */
public interface Parameterizable {

    /**
     * Gets the {@link Map} of available parameters for the test to use.
     *
     * @return a {@link Map} of {@link BaseParameter} objects.
     */
    Map<String, BaseParameter> getAvailableParameters();


    /**
     * Setter method for {@link Parameter.Reader}.
     *
     * @param parameterReader the {@link Parameter.Reader} to set.
     */
    void setParameterReader(Parameter.Reader parameterReader);

    /**
     * Gets a specific parameter from the current test.
     *
     * @param parameterTag a string with the name of the {@link BaseParameter} we want.
     * @return a parameter that extends {@link BaseParameter} that has the matching parameterTag.
     */
    <T extends BaseParameter> T getAvailableParameter(String parameterTag);
}
