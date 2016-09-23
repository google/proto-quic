// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.util.parameter.parameters;

import org.chromium.base.test.util.parameter.BaseParameter;
import org.chromium.base.test.util.parameter.Parameter;

/**
 * Allows for passing of certain parameters arguments to function when this parameter is used.
 */
public class MethodParameter extends BaseParameter {
    public static final String PARAMETER_TAG = "method-parameter";

    public MethodParameter(Parameter.Reader parameterReader) {
        super(PARAMETER_TAG, parameterReader);
    }
}


