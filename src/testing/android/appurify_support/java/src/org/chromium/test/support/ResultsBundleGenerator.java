// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.test.support;

import android.os.Bundle;

import java.util.List;
import java.util.Map;

/**
 * Creates a results Bundle.
 */
public interface ResultsBundleGenerator {
    /**
     * Holds the results of a test.
     */
    public interface TestResult {
        /**
         * Returns the test class name.
         */
        public String getTestClass();

        /**
         * Returns the test case name.
         */
        public String getTestName();

        /**
         * Retunrs the index of the test within the suite.
         */
        public int getTestIndex();

        /**
         * Returns a message for the test.
         */
        public String getMessage();

        /**
         * Returns the test case log.
         */
        public String getLog();

        /**
         * Returns the status of the test.
         */
        public TestStatus getStatus();
    }

    /** Indicates the state of a test.
     */
    public static enum TestStatus { PASSED, FAILED, ERROR, UNKNOWN }

    /** Holds the processed data to be sent by the Instrumentation to report the status of a test
        case.
     */
    public static class TestCaseResult {
        public final Bundle mBundle;
        public final int mStatusCode;

        public TestCaseResult(int statusCode, Bundle bundle) {
            mBundle = bundle;
            mStatusCode = statusCode;
        }
    }

    /** Generates intermediate results for each individual test case to be sent to the
        instrumentation framework.

        @returns a list of TestCaseResults that can be used to send status updates.

        Note: actual bundle content and format may vary.

        @param rawResults A map between test names and test results.
     */
    List<TestCaseResult> generateIntermediateTestResults(Map<String, TestResult> rawResults);

    /**
      Creates a bundle of test results from the provided raw results.

      Note: actual bundle content and format may vary.
      @param testsPassed The number of passed test cases.
      @param testsFailed The number of failed test cases.
      @param testsErrored The number of errored test cases.
      @param totalTests The number of test cases.
     */
    Bundle generate(int testsPassed, int testsFailed, int testsErrored, int totalTests);
}
