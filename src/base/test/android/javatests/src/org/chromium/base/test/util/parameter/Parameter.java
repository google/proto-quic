// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.util.parameter;

import junit.framework.TestCase;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * The annotation for an individual parameter in a {@link ParameterizedTest}.
 *
 * Contains all annotations required to run tests ParameterizedTests.
 */
public @interface Parameter {
    String tag();
    Argument[] arguments() default {};

    /**
     * The annotation for an individual argument in a {@link Parameter}.
     */
    @interface Argument {
        String name();
        String stringVar() default Parameter.ArgumentDefault.STRING;
        String[] stringArray() default {};
        int intVar() default Parameter.ArgumentDefault.INT;
        int[] intArray() default {};
    }

    /**
     * Default values for {@link Parameter.Argument}s.
     *
     * TODO (crbug.com/520232): Move to within {@link Parameter.Argument} and rename to Default
     * when fixed.
     */
    final class ArgumentDefault {
        public static final String STRING = "";
        public static final int INT = 0;
    }

    /**
     * The tool to read Parameter related annotations.
     */
    class Reader {
        private Class mAnnotatedTestClass;
        private AnnotatedElement mAnnotatedTestMethod;
        private ParameterizedTest mParameterizedTest;

        public Reader(TestCase testCase) {
            try {
                mAnnotatedTestClass = testCase.getClass();
                mAnnotatedTestMethod = testCase.getClass().getMethod(testCase.getName());
            } catch (NoSuchMethodException e) {
                // ignore
            }
        }

        /**
         * Gets the {@link ParameterizedTest}s for the current test.
         *
         * @return a list of all the {@link ParameterizedTest}s for the current test.
         */
        public List<ParameterizedTest> getParameterizedTests() {
            return new ArrayList<ParameterizedTest>(getParameterizedTestsImpl());
        }

        /**
         * Gets the {@link ParameterizedTest}s for the current test as immutable list.
         *
         * @return a list of all the {@link ParameterizedTest}s for the current test.
         */
        private List<ParameterizedTest> getParameterizedTestsImpl() {
            // Note: this must be aligned with Python code in
            // instrumentation_test_instance.ParseCommandLineFlagParameters (regarding priority of
            // ParameterizedTest.Set vs. ParameterizedTest) and in test_jar._GetProguardData
            // (regarding composition of method annotations with class and superclasses
            // annotations). Composition precedes selecting the annotation to process.
            if (mAnnotatedTestMethod.isAnnotationPresent(ParameterizedTest.Set.class)) {
                return Arrays.asList(getParameterizedTestSet(mAnnotatedTestMethod).tests());
            }
            AnnotatedElement classWithAnnotation = findClassWithAnnotation(
                    mAnnotatedTestClass, ParameterizedTest.Set.class);
            if (classWithAnnotation != null) {
                return Arrays.asList(getParameterizedTestSet(classWithAnnotation).tests());
            }
            if (mAnnotatedTestMethod.isAnnotationPresent(ParameterizedTest.class)) {
                return Collections.singletonList(getParameterizedTest(mAnnotatedTestMethod));
            }
            classWithAnnotation = findClassWithAnnotation(
                    mAnnotatedTestClass, ParameterizedTest.class);
            if (classWithAnnotation != null) {
                return Collections.singletonList(getParameterizedTest(classWithAnnotation));
            }
            return Collections.emptyList();
        }

        /**
         * Finds a class with the given annotation class starting from the given clazz.
         *
         * @return the class as {@link AnnotatedElement} or null if the class is not found.
         */
        private AnnotatedElement findClassWithAnnotation(
                Class<?> clazz, Class<? extends Annotation> annotationClass) {
            if (clazz == null || clazz.isAnnotationPresent(annotationClass)) {
                return clazz;
            } else {
                return findClassWithAnnotation(clazz.getSuperclass(), annotationClass);
            }
        }

        /**
         * Gets the {@link ParameterizedTest} annotation of the current test.
         *
         * @return a {@link ParameterizedTest} of the current test's parameters.
         */
        private ParameterizedTest getParameterizedTest(AnnotatedElement element) {
            return element.getAnnotation(ParameterizedTest.class);
        }

        /**
         * Gets the {@link ParameterizedTest.Set} annotation of the current test.
         *
         * @return a {@link ParameterizedTest.Set} of the current test's parameters.
         */
        private ParameterizedTest.Set getParameterizedTestSet(AnnotatedElement element) {
            return element.getAnnotation(ParameterizedTest.Set.class);
        }

        public boolean isParameterizedTest() {
            return mAnnotatedTestMethod.isAnnotationPresent(ParameterizedTest.Set.class)
                    || mAnnotatedTestMethod.isAnnotationPresent(ParameterizedTest.class)
                    || findClassWithAnnotation(
                            mAnnotatedTestClass, ParameterizedTest.Set.class) != null
                    || findClassWithAnnotation(
                            mAnnotatedTestClass, ParameterizedTest.class) != null;
        }

        public void setCurrentParameterizedTest(ParameterizedTest parameterizedTest) {
            mParameterizedTest = parameterizedTest;
        }

        /**
         * Gets a {@link Parameter} object for a given target parameter.
         *
         * @param targetParameter the name of the {@link Parameter} to get in the current
         * parameterized test.
         * @return the {@link Parameter} for a given {@link ParameterizedTest} with the
         * targetParameter as its tag if it exists, otherwise returns null.
         */
        public Parameter getParameter(String targetParameter) {
            if (mParameterizedTest == null || targetParameter == null) {
                return null;
            }
            for (Parameter parameter : mParameterizedTest.parameters()) {
                if (targetParameter.equals(parameter.tag())) {
                    return parameter;
                }
            }
            return null;
        }

        /**
         * Gets the {@link Parameter.Argument} for a given {@link Parameter}.
         *
         * @param targetParameter the name of the {@link Parameter} to search for when looking for
         * a {@link Parameter.Argument}.
         * @param targetArgument the name of the {@link Parameter.Argument} to look for in the
         * target {@link Parameter}.
         * @return the {@link Parameter.Argument} for a given {@link ParameterizedTest} for the
         * {@link Parameter} with the tag matching targetParameter and the argument name being
         * targetArgument if it exists, otherwise returns null.
         */
        public Parameter.Argument getParameterArgument(String targetParameter,
                String targetArgument) {
            Parameter parameter = getParameter(targetParameter);
            return (parameter == null) ? null : getParameterArgument(parameter, targetArgument);
        }

        public static Parameter.Argument getParameterArgument(Parameter parameter,
                String targetArgument) {
            if (targetArgument == null) {
                return null;
            }
            for (Parameter.Argument argument : parameter.arguments()) {
                if (targetArgument.equals(argument.name())) {
                    return argument;
                }
            }
            return null;
        }
    }
}

