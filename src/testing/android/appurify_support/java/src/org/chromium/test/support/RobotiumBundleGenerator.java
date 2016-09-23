// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.test.support;

import android.app.Instrumentation;
import android.os.Bundle;
import android.test.InstrumentationTestRunner;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Creates a results bundle that emulates the one created by Robotium.
 */
public class RobotiumBundleGenerator implements ResultsBundleGenerator {
    private static final String TAG = "RobotiumBundleGenerator";

    public List<ResultsBundleGenerator.TestCaseResult> generateIntermediateTestResults(
            Map<String, ResultsBundleGenerator.TestResult> rawResults) {
        if (rawResults.isEmpty()) {
            return new ArrayList<ResultsBundleGenerator.TestCaseResult>();
        }

        List<ResultsBundleGenerator.TestCaseResult> testCaseResultList =
                new ArrayList<ResultsBundleGenerator.TestCaseResult>();
        int totalTests = rawResults.size();

        for (Map.Entry<String, ResultsBundleGenerator.TestResult> entry : rawResults.entrySet()) {
            ResultsBundleGenerator.TestResult result = entry.getValue();
            Bundle startBundle = new Bundle();
            startBundle.putString(Instrumentation.REPORT_KEY_IDENTIFIER,
                    InstrumentationTestRunner.REPORT_VALUE_ID);
            startBundle.putString(
                    InstrumentationTestRunner.REPORT_KEY_NAME_CLASS, result.getTestClass());
            startBundle.putString(
                    InstrumentationTestRunner.REPORT_KEY_NAME_TEST, result.getTestName());
            startBundle.putInt(
                    InstrumentationTestRunner.REPORT_KEY_NUM_CURRENT, result.getTestIndex());
            startBundle.putInt(InstrumentationTestRunner.REPORT_KEY_NUM_TOTAL, totalTests);
            startBundle.putString(Instrumentation.REPORT_KEY_STREAMRESULT,
                    String.format("%n%s.%s", result.getTestClass(), result.getTestName()));
            testCaseResultList.add(new ResultsBundleGenerator.TestCaseResult(
                    InstrumentationTestRunner.REPORT_VALUE_RESULT_START, startBundle));

            Bundle resultBundle = new Bundle(startBundle);
            resultBundle.putString(Instrumentation.REPORT_KEY_STREAMRESULT, result.getMessage());
            switch (result.getStatus()) {
                case PASSED:
                    testCaseResultList.add(new ResultsBundleGenerator.TestCaseResult(
                            InstrumentationTestRunner.REPORT_VALUE_RESULT_OK, resultBundle));
                    break;
                case FAILED:
                    // TODO(jbudorick): Remove this log message once AMP execution and
                    // results handling has been stabilized.
                    Log.d(TAG, "FAILED: " + entry.getKey());
                    resultBundle.putString(
                            InstrumentationTestRunner.REPORT_KEY_STACK, result.getLog());
                    testCaseResultList.add(new ResultsBundleGenerator.TestCaseResult(
                            InstrumentationTestRunner.REPORT_VALUE_RESULT_FAILURE, resultBundle));
                    break;
                case UNKNOWN:
                    testCaseResultList.add(new ResultsBundleGenerator.TestCaseResult(
                            InstrumentationTestRunner.REPORT_VALUE_RESULT_ERROR, resultBundle));
                    break;
                default:
                    Log.w(TAG, "Unhandled: " + entry.getKey() + ", "
                            + entry.getValue().toString());
                    testCaseResultList.add(new ResultsBundleGenerator.TestCaseResult(
                            InstrumentationTestRunner.REPORT_VALUE_RESULT_ERROR, resultBundle));
                    break;
            }
        }
        return testCaseResultList;
    }

    public Bundle generate(int testsPassed, int testsFailed, int testsErrored, int totalTests) {
        Bundle resultsBundle = new Bundle();
        StringBuilder resultBuilder = new StringBuilder();
        if (testsFailed > 0 || testsErrored > 0) {
            resultBuilder.append("\nFAILURES!!! ")
                    .append("Tests run: ")
                    .append(Integer.toString(totalTests))
                    .append(", Failures: ")
                    .append(Integer.toString(testsFailed))
                    .append(", Errors: ")
                    .append(Integer.toString(testsErrored));
        } else {
            resultBuilder.append("\nOK (" + Integer.toString(testsPassed) + " tests)");
        }

        resultsBundle.putString(Instrumentation.REPORT_KEY_STREAMRESULT,
                resultBuilder.toString());
        return resultsBundle;
    }
}
