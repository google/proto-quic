// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.util.parameter;

/**
 * The attributes of a single parameter.
 */
public class BaseParameter {
    private final String mTag;
    private final Parameter.Reader mParameterReader;

    public BaseParameter(String tag, Parameter.Reader parameterReader) {
        mTag = tag;
        mParameterReader = parameterReader;
    }

    public String getTag() {
        return mTag;
    }

    public String getStringArgument(String argumentName, String defaultString) {
        Parameter.Argument parameterArgument = getArgument(argumentName);
        return parameterArgument != null ? parameterArgument.stringVar() : defaultString;
    }

    public String getStringArgument(String argumentName) {
        Parameter.Argument parameterArgument = getArgument(argumentName);
        checkArgumentExists(parameterArgument);
        return parameterArgument.stringVar();
    }

    public int getIntArgument(String argumentName, int defaultInt) {
        Parameter.Argument parameterArgument = getArgument(argumentName);
        return parameterArgument != null ? parameterArgument.intVar() : defaultInt;
    }

    public int getIntArgument(String argumentName) {
        Parameter.Argument parameterArgument = getArgument(argumentName);
        checkArgumentExists(parameterArgument);
        return parameterArgument.intVar();
    }

    public String[] getStringArrayArgument(String argumentName, String[] defaultStringArray) {
        Parameter.Argument parameterArgument = getArgument(argumentName);
        return parameterArgument != null ? parameterArgument.stringArray() : defaultStringArray;
    }

    public String[] getStringArrayArgument(String argumentName) {
        Parameter.Argument parameterArgument = getArgument(argumentName);
        checkArgumentExists(parameterArgument);
        return parameterArgument.stringArray();
    }

    public int[] getIntArrayArgument(String argumentName, int[] defaultIntArray) {
        Parameter.Argument parameterArgument = getArgument(argumentName);
        return parameterArgument != null ? parameterArgument.intArray() : defaultIntArray;
    }

    public int[] getIntArrayArgument(String argumentName) {
        Parameter.Argument parameterArgument = getArgument(argumentName);
        checkArgumentExists(parameterArgument);
        return parameterArgument.intArray();
    }

    private Parameter.Argument getArgument(String argumentName) {
        return mParameterReader.getParameterArgument(getTag(), argumentName);
    }

    private static void checkArgumentExists(Parameter.Argument parameterArgument) {
        if (parameterArgument == null) {
            throw new IllegalArgumentException("Argument must be specified");
        }
    }

    public void setUp() throws Exception {}

    public void tearDown() throws Exception {}
}
