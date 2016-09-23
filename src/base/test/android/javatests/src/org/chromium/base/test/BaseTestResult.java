// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test;

import android.app.Instrumentation;
import android.content.Context;
import android.os.Bundle;
import android.os.SystemClock;

import junit.framework.AssertionFailedError;
import junit.framework.TestCase;
import junit.framework.TestResult;

import org.chromium.base.Log;
import org.chromium.base.test.util.CommandLineFlags;
import org.chromium.base.test.util.SkipCheck;
import org.chromium.base.test.util.parameter.BaseParameter;
import org.chromium.base.test.util.parameter.Parameter;
import org.chromium.base.test.util.parameter.Parameterizable;
import org.chromium.base.test.util.parameter.ParameterizedTest;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * A test result that can skip tests.
 */
public class BaseTestResult extends TestResult {
    private static final String TAG = "base_test";

    private static final int SLEEP_INTERVAL_MS = 50;
    private static final int WAIT_DURATION_MS = 5000;

    private final Instrumentation mInstrumentation;
    private final List<SkipCheck> mSkipChecks;
    private final List<PreTestHook> mPreTestHooks;

    /**
     * Creates an instance of BaseTestResult.
     */
    public BaseTestResult(Instrumentation instrumentation) {
        mSkipChecks = new ArrayList<>();
        mPreTestHooks = new ArrayList<>();
        mInstrumentation = instrumentation;
    }

    /**
     * An interface for classes that have some code to run before a test. They run after
     * {@link SkipCheck}s. Provides access to the test method (and the annotations defined for it)
     * and the instrumentation context.
     */
    public interface PreTestHook {
        /**
         * @param targetContext the instrumentation context that will be used during the test.
         * @param testMethod the test method to be run.
         */
        public void run(Context targetContext, Method testMethod);
    }

    /**
     * Adds a check for whether a test should run.
     *
     * @param skipCheck The check to add.
     */
    public void addSkipCheck(SkipCheck skipCheck) {
        mSkipChecks.add(skipCheck);
    }

    /**
     * Adds hooks that will be executed before each test that runs.
     *
     * @param preTestHook The hook to add.
     */
    public void addPreTestHook(PreTestHook preTestHook) {
        mPreTestHooks.add(preTestHook);
    }

    protected boolean shouldSkip(TestCase test) {
        for (SkipCheck s : mSkipChecks) {
            if (s.shouldSkip(test)) return true;
        }
        return false;
    }

    private void runPreTestHooks(TestCase test) {
        try {
            Method testMethod = test.getClass().getMethod(test.getName());
            Context targetContext = getTargetContext();

            for (PreTestHook hook : mPreTestHooks) {
                hook.run(targetContext, testMethod);
            }
        } catch (NoSuchMethodException e) {
            Log.e(TAG, "Unable to run pre test hooks.", e);
        }
    }

    @Override
    protected void run(TestCase test) {
        runPreTestHooks(test);

        if (shouldSkip(test)) {
            startTest(test);

            Bundle skipResult = new Bundle();
            skipResult.putString("class", test.getClass().getName());
            skipResult.putString("test", test.getName());
            skipResult.putBoolean("test_skipped", true);
            mInstrumentation.sendStatus(0, skipResult);

            endTest(test);
        } else {
            if (test instanceof Parameterizable) {
                try {
                    runParameterized(test);
                } catch (ThreadDeath e) {
                    Log.e(TAG, "Parameterized test run failed: %s", e);
                }
            } else {
                super.run(test);
            }
        }
    }

    @SuppressWarnings("unchecked")
    private <T extends TestCase & Parameterizable> void runParameterized(TestCase test)
            throws ThreadDeath {
        T testCase = (T) test;

        // Prepare test.
        Parameter.Reader parameterReader = new Parameter.Reader(test);
        testCase.setParameterReader(parameterReader);
        List<ParameterizedTest> parameterizedTests = parameterReader.getParameterizedTests();
        List<ParameterError> errors = new ArrayList<>();
        List<ParameterError> failures = new ArrayList<>();
        Map<String, BaseParameter> availableParameters = testCase.getAvailableParameters();

        // Remove all @ParameterizedTests that contain CommandLineFlags.Parameter -- those
        // are handled in test_runner.py as it is needed to re-launch the whole test activity
        // to apply command-line args correctly. Note that this way we will also ignore any
        // other parameters that may present in these @ParameterizedTests.
        for (Iterator<ParameterizedTest> iter = parameterizedTests.iterator(); iter.hasNext();) {
            ParameterizedTest paramTest = iter.next();
            for (Parameter p: paramTest.parameters()) {
                if (CommandLineFlags.Parameter.PARAMETER_TAG.equals(p.tag())) {
                    iter.remove();
                }
            }
        }

        if (parameterizedTests.isEmpty()) {
            super.run(test);
        } else {
            // Start test.
            startTest(testCase);
            for (ParameterizedTest parameterizedTest : parameterizedTests) {
                parameterReader.setCurrentParameterizedTest(parameterizedTest);
                try {
                    setUpParameters(availableParameters, parameterReader);
                    testCase.runBare();
                    tearDownParameters(availableParameters, parameterReader);
                } catch (AssertionFailedError e) {
                    failures.add(new ParameterError(e, parameterizedTest));
                } catch (ThreadDeath e) {
                    throw e;
                } catch (Throwable e) {
                    errors.add(new ParameterError(e, parameterizedTest));
                }
            }

            // Generate failures and errors.
            if (!failures.isEmpty()) {
                addFailure(test, new ParameterizedTestFailure(failures));
            }
            if (!errors.isEmpty()) {
                addError(test, new ParameterizedTestError(errors));
            }

            // End test.
            endTest(testCase);
        }
    }

    private static <T extends TestCase & Parameterizable> void setUpParameters(
            Map<String, BaseParameter> availableParameters, Parameter.Reader reader)
            throws Exception {
        for (Entry<String, BaseParameter> entry : availableParameters.entrySet()) {
            if (reader.getParameter(entry.getValue().getTag()) != null) {
                entry.getValue().setUp();
            }
        }
    }

    private static <T extends TestCase & Parameterizable> void tearDownParameters(
            Map<String, BaseParameter> availableParameters, Parameter.Reader reader)
            throws Exception {
        for (Entry<String, BaseParameter> entry : availableParameters.entrySet()) {
            if (reader.getParameter(entry.getValue().getTag()) != null) {
                entry.getValue().tearDown();
            }
        }
    }

    private static class ParameterError {
        private final Throwable mThrowable;
        private final ParameterizedTest mParameterizedTest;

        public ParameterError(Throwable throwable, ParameterizedTest parameterizedTest) {
            mThrowable = throwable;
            mParameterizedTest = parameterizedTest;
        }

        private Throwable getThrowable() {
            return mThrowable;
        }

        private ParameterizedTest getParameterizedTest() {
            return mParameterizedTest;
        }
    }

    private static class ParameterizedTestFailure extends AssertionFailedError {
        public ParameterizedTestFailure(List<ParameterError> failures) {
            super(new ParameterizedTestError(failures).toString());
        }
    }

    private static class ParameterizedTestError extends Exception {
        private final List<ParameterError> mErrors;

        public ParameterizedTestError(List<ParameterError> errors) {
            mErrors = errors;
        }

        /**
         * Error output is as follows.
         *
         * DEFINITIONS:
         * {{ERROR}} is the standard error output from
         * {@link ParameterError#getThrowable().toString()}.
         * {{PARAMETER_TAG}} is the {@link Parameter#tag()} value associated with the parameter.
         * {{ARGUMENT_NAME}} is the {@link Parameter.Argument#name()} associated with the argument.
         * {{ARGUMENT_VALUE}} is the value associated with the {@link Parameter.Argument}. This can
         * be a String, int, String[], or int[].
         *
         * With no {@link Parameter}:
         * {{ERROR}} (with no parameters)
         *
         * With Single {@link Parameter} and no {@link Parameter.Argument}:
         * {{ERROR}} (with parameters: {{PARAMETER_TAG}} with no arguments)
         *
         * With Single {@link Parameter} and one {@link Parameter.Argument}:
         * {{ERROR}} (with parameters: {{PARAMETER_TAG}} with arguments:
         * {{ARGUMENT_NAME}}={{ARGUMENT_VALUE}})
         *
         * With Single {@link Parameter} and multiple {@link Parameter.Argument}s:
         * {{ERROR}} (with parameters: {{PARAMETER_TAG}} with arguments:
         * {{ARGUMENT_NAME}}={{ARGUMENT_VALUE}}, {{ARGUMENT_NAME}}={{ARGUMENT_VALUE}}, ...)
         *
         * DEFINITION:
         * {{PARAMETER_ERROR}} is the output of a single {@link Parameter}'s error. Format:
         * {{PARAMETER_TAG}} with arguments: {{ARGUMENT_NAME}}={{ARGUMENT_NAME}}, ...
         *
         * With Multiple {@link Parameter}s:
         * {{ERROR}} (with parameters: {{PARAMETER_ERROR}}; {{PARAMETER_ERROR}}; ...)
         *
         * There will be a trace after this. And this is shown for every possible {@link
         * ParameterizedTest} that is failed in the {@link ParameterizedTest.Set} if there is one.
         *
         * @return the error message and trace of the test failures.
         */
        @Override
        public String toString() {
            if (mErrors.isEmpty()) return "\n";
            StringBuilder builder = new StringBuilder();
            Iterator<ParameterError> iter = mErrors.iterator();
            if (iter.hasNext()) {
                builder.append(createErrorBuilder(iter.next()));
            }
            while (iter.hasNext()) {
                builder.append("\n").append(createErrorBuilder(iter.next()));
            }
            return builder.toString();
        }

        private static StringBuilder createErrorBuilder(ParameterError error) {
            StringBuilder builder = new StringBuilder("\n").append(error.getThrowable().toString());
            List<Parameter> parameters =
                    Arrays.asList(error.getParameterizedTest().parameters());
            if (parameters.isEmpty()) {
                builder.append(" (with no parameters)");
            } else {
                Iterator<Parameter> iter = parameters.iterator();
                builder.append(" (with parameters: ").append(createParameterBuilder(iter.next()));
                while (iter.hasNext()) {
                    builder.append("; ").append(createParameterBuilder(iter.next()));
                }
                builder.append(")");
            }
            return builder.append("\n").append(trace(error));
        }

        private static StringBuilder createParameterBuilder(Parameter parameter) {
            StringBuilder builder = new StringBuilder(parameter.tag());
            List<Parameter.Argument> arguments = Arrays.asList(parameter.arguments());
            if (arguments.isEmpty()) {
                builder.append(" with no arguments");
            } else {
                Iterator<Parameter.Argument> iter = arguments.iterator();
                builder.append(" with arguments: ").append(createArgumentBuilder(iter.next()));
                while (iter.hasNext()) {
                    builder.append(", ").append(createArgumentBuilder(iter.next()));
                }
            }
            return builder;
        }

        private static StringBuilder createArgumentBuilder(Parameter.Argument argument) {
            StringBuilder builder = new StringBuilder(argument.name()).append("=");
            if (!Parameter.ArgumentDefault.STRING.equals(argument.stringVar())) {
                builder.append(argument.stringVar());
            } else if (Parameter.ArgumentDefault.INT != argument.intVar()) {
                builder.append(argument.intVar());
            } else if (argument.stringArray().length > 0) {
                builder.append(Arrays.toString(argument.stringArray()));
            } else if (argument.intArray().length > 0) {
                builder.append(Arrays.toString(argument.intArray()));
            }
            return builder;
        }

        /**
         * @return the trace without the error message
         */
        private static StringBuilder trace(ParameterError error) {
            StringWriter stringWriter = new StringWriter();
            PrintWriter writer = new PrintWriter(stringWriter);
            error.getThrowable().printStackTrace(writer);
            StringBuilder builder = new StringBuilder(stringWriter.getBuffer());
            return trim(deleteFirstLine(builder));
        }

        private static StringBuilder deleteFirstLine(StringBuilder builder) {
            return builder.delete(0, builder.indexOf("\n") + 1);
        }

        private static StringBuilder trim(StringBuilder sb) {
            if (sb == null || sb.length() == 0) return sb;
            for (int i = sb.length() - 1; i >= 0; i--) {
                if (Character.isWhitespace(sb.charAt(i))) {
                    sb.deleteCharAt(i);
                } else {
                    return sb;
                }
            }
            return sb;
        }
    }

    /**
     * Gets the target context.
     *
     * On older versions of Android, getTargetContext() may initially return null, so we have to
     * wait for it to become available.
     *
     * @return The target {@link Context} if available; null otherwise.
     */
    public Context getTargetContext() {
        Context targetContext = mInstrumentation.getTargetContext();
        try {
            long startTime = SystemClock.uptimeMillis();
            // TODO(jbudorick): Convert this to CriteriaHelper once that moves to base/.
            while (targetContext == null
                    && SystemClock.uptimeMillis() - startTime < WAIT_DURATION_MS) {
                Thread.sleep(SLEEP_INTERVAL_MS);
                targetContext = mInstrumentation.getTargetContext();
            }
        } catch (InterruptedException e) {
            Log.e(TAG, "Interrupted while attempting to initialize the command line.");
        }
        return targetContext;
    }
}
