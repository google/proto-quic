// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.params;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runners.model.FrameworkMethod;
import org.junit.runners.model.TestClass;

import org.chromium.base.test.params.ParameterAnnotations.UseMethodParameter;
import org.chromium.base.test.params.ParameterizedRunner.ParameterizedTestInstantiationException;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

/**
 * Factory to generate delegate class runners for ParameterizedRunner
 */
public class ParameterizedRunnerDelegateFactory {
    /**
     * Create a runner that implements ParameterizedRunner and extends BlockJUnit4ClassRunner
     *
     * @param testClass the TestClass object for current test class
     * @param classParameterSet A parameter set for test constructor arguments
     * @param testMethodToParameterSetListMap maps annotation tag to list of parameter set
     * @param parameterizedRunnerDelegateClass the parameterized runner delegate class specified
     *                                         through {@code @UseRunnerDelegate}
     */
    <T extends ParameterizedRunnerDelegate> T createRunner(TestClass testClass,
            ParameterSet classParameterSet,
            Map<String, List<ParameterSet>> testMethodToParameterSetListMap,
            Class<T> parameterizedRunnerDelegateClass)
            throws ParameterizedTestInstantiationException,
                   ParameterizedRunnerDelegateInstantiationException {
        String testMethodPostfix = classParameterSet == null ? null : classParameterSet.getName();
        List<FrameworkMethod> unmodifiableFrameworkMethodList =
                generateUnmodifiableFrameworkMethodList(
                        testClass, testMethodToParameterSetListMap, testMethodPostfix);
        Object test = createTest(testClass, classParameterSet);
        ParameterizedRunnerDelegateCommon delegateCommon =
                new ParameterizedRunnerDelegateCommon(test, unmodifiableFrameworkMethodList);
        try {
            T runnerDelegate = parameterizedRunnerDelegateClass
                                       .getDeclaredConstructor(
                                               Class.class, ParameterizedRunnerDelegateCommon.class)
                                       .newInstance(testClass.getJavaClass(), delegateCommon);
            return runnerDelegate;
        } catch (Exception e) {
            throw new ParameterizedRunnerDelegateInstantiationException(
                    parameterizedRunnerDelegateClass.toString(), e);
        }
    }

    /**
     * Match test methods annotated by @UseMethodParameter(X) with
     * ParameterSetList annotated by @MethodParameter(X)
     *
     * @param testClass a {@code TestClass} that wraps around the actual java
     *            test class
     * @param tagToParameterSetList A map of String tags to ParameterSetList
     * @param postFix a name postfix for each test
     * @return a list of ParameterizedFrameworkMethod
     */
    static List<FrameworkMethod> generateUnmodifiableFrameworkMethodList(TestClass testClass,
            Map<String, List<ParameterSet>> tagToParameterSetList, String postFix) {
        // A Map that maps string tag X to a list of test framework methods that are
        // annotated with @UseMethodParameter(X)
        Map<String, List<FrameworkMethod>> tagToListOfFrameworkMethod = new HashMap<>();

        // Represent the list of all ParameterizedFrameworkMethod in this test class
        List<FrameworkMethod> returnList = new ArrayList<>();

        // Create tagToListOfFrameworkMethod
        for (FrameworkMethod method : testClass.getAnnotatedMethods(Test.class)) {
            // If test method is not parameterized (does not have
            // UseMethodParameter annotation)
            if (!method.getMethod().isAnnotationPresent(UseMethodParameter.class)) {
                returnList.add(new ParameterizedFrameworkMethod(method.getMethod(), null, postFix));
            } else {
                String currentGroup = method.getAnnotation(UseMethodParameter.class).value();
                if (tagToListOfFrameworkMethod.get(currentGroup) == null) {
                    List<FrameworkMethod> list = new ArrayList<>();
                    list.add(method);
                    tagToListOfFrameworkMethod.put(currentGroup, list);
                } else {
                    tagToListOfFrameworkMethod.get(currentGroup).add(method);
                }
            }
        }

        Assert.assertArrayEquals(
                "All parameters used by must be defined, and all defined parameters must be used.",
                tagToParameterSetList.keySet().toArray(),
                tagToListOfFrameworkMethod.keySet().toArray());

        // Loop through each of the tags and create all the parameterized framework
        // methods for every method parameter set in the method parameter set list
        // annotated with that tag
        for (Entry<String, List<ParameterSet>> entry : tagToParameterSetList.entrySet()) {
            String tagString = entry.getKey();
            List<ParameterSet> parameterSetList = entry.getValue();
            for (FrameworkMethod method : tagToListOfFrameworkMethod.get(tagString)) {
                for (ParameterSet set : parameterSetList) {
                    if (set.getValues() == null) {
                        throw new IllegalArgumentException(
                                "No parameter is added to method ParameterSet");
                    }
                    returnList.add(
                            new ParameterizedFrameworkMethod(method.getMethod(), set, postFix));
                }
            }
        }
        return Collections.unmodifiableList(returnList);
    }

    /**
     * Create a test object using the list of class parameter set
     *
     * @param testClass the {@link TestClass} object for current test class
     * @param classParameterSet the parameter set needed for the test class constructor
     */
    static Object createTest(TestClass testClass, ParameterSet classParameterSet)
            throws ParameterizedTestInstantiationException {
        try {
            if (classParameterSet == null) {
                return testClass.getOnlyConstructor().newInstance();
            }
            return testClass.getOnlyConstructor().newInstance(
                    classParameterSet.getValues().toArray());
        } catch (Exception e) {
            String parameterSetString =
                    classParameterSet == null ? "null" : classParameterSet.toString();
            throw new ParameterizedTestInstantiationException(testClass, parameterSetString, e);
        }
    }

    /**
     * Exception caused by instantiating the provided Runner delegate
     * Potentially caused by not overriding collecInitializationErrors() method
     * to be empty
     */
    public static class ParameterizedRunnerDelegateInstantiationException extends Exception {
        private ParameterizedRunnerDelegateInstantiationException(
                String runnerDelegateClass, Exception e) {
            super(String.format("Current class runner delegate %s can not be instantiated.",
                          runnerDelegateClass),
                    e);
        }
    }
}
