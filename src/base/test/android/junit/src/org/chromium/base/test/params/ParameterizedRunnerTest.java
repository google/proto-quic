// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.params;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runner.Runner;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.model.TestClass;

import org.chromium.base.test.params.ParameterAnnotations.ClassParameter;
import org.chromium.base.test.params.ParameterAnnotations.MethodParameter;
import org.chromium.base.test.params.ParameterAnnotations.UseMethodParameter;
import org.chromium.base.test.params.ParameterAnnotations.UseRunnerDelegate;
import org.chromium.base.test.params.ParameterizedRunner.IllegalParameterArgumentException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Test for org.chromium.base.test.params.ParameterizedRunner
 */
@RunWith(BlockJUnit4ClassRunner.class)
public class ParameterizedRunnerTest {
    @UseRunnerDelegate(BlockJUnit4RunnerDelegate.class)
    public static class TestClassWithPrivateParameterSetList {
        @ClassParameter
        private static List<ParameterSet> sClassParams = new ArrayList<>();

        static {
            sClassParams.add(new ParameterSet().value(1));
            sClassParams.add(new ParameterSet().value(2));
        }

        @MethodParameter("A")
        private static List<ParameterSet> sMethodParamA = new ArrayList<>();

        static {
            sMethodParamA.add(new ParameterSet().value("a", "b"));
        }

        public TestClassWithPrivateParameterSetList(int x) {}

        @Test
        @UseMethodParameter("A")
        public void test(String a, String b) {}
    }

    @UseRunnerDelegate(BlockJUnit4RunnerDelegate.class)
    public static class TestClassWithDefaultParameterSetList {
        @ClassParameter
        static List<ParameterSet> sClassParams = new ArrayList<>();

        static {
            sClassParams.add(new ParameterSet().value(1, 2));
        }

        @MethodParameter("A")
        static List<ParameterSet> sMethodParamA = new ArrayList<>();

        static {
            sMethodParamA.add(new ParameterSet().value(null));
        }

        public TestClassWithDefaultParameterSetList(int a, int b) {}

        @Test
        @UseMethodParameter("A")
        public void test(String x) {}
    }

    @UseRunnerDelegate(BlockJUnit4RunnerDelegate.class)
    public static class BadTestClassWithMoreThanOneConstructor {
        @ClassParameter
        static List<ParameterSet> sClassParams = new ArrayList<>();

        public BadTestClassWithMoreThanOneConstructor() {}

        public BadTestClassWithMoreThanOneConstructor(String x) {}
    }

    @UseRunnerDelegate(BlockJUnit4RunnerDelegate.class)
    public static class BadTestClassWithNonListParameters {
        @ClassParameter
        static String[] sMethodParamA = {"1", "2"};

        @Test
        public void test() {}
    }

    @UseRunnerDelegate(BlockJUnit4RunnerDelegate.class)
    public static class BadTestClassWithoutNeedForParameterization {
        @Test
        public void test() {}
    }

    @UseRunnerDelegate(BlockJUnit4RunnerDelegate.class)
    public static class BadTestClassWithNonStaticParameterSetList {
        @ClassParameter
        public List<ParameterSet> sClassParams = new ArrayList<>();

        @Test
        public void test() {}
    }

    @UseRunnerDelegate(BlockJUnit4RunnerDelegate.class)
    public static class BadTestClassWithMissingMethodParameter {
        @MethodParameter("A")
        private static List<ParameterSet> sParameterSetListA = new ArrayList<>();

        @MethodParameter("B")
        private static List<ParameterSet> sParameterSetListB = new ArrayList<>();

        @Test
        @UseMethodParameter("A")
        public void testA() {}
    }

    @UseRunnerDelegate(BlockJUnit4RunnerDelegate.class)
    public static class BadTestClassWithMultipleClassParameter {
        @ClassParameter
        private static List<ParameterSet> sParamA = new ArrayList<>();

        @ClassParameter
        private static List<ParameterSet> sParamB = new ArrayList<>();
    }

    @Test
    public void testPrivateAccessible() throws Throwable {
        TestClass testClass = new TestClass(TestClassWithPrivateParameterSetList.class);
        List<Runner> runners = ParameterizedRunner.createRunners(testClass);
        Assert.assertEquals(runners.size(), 2);
        Map<String, List<ParameterSet>> generatedMap =
                ParameterizedRunner.generateMethodParameterMap(testClass);
        Assert.assertEquals(generatedMap.keySet().size(), 1);
        Assert.assertTrue(generatedMap.keySet().contains("A"));
        Assert.assertEquals(generatedMap.get("A").size(), 1);
    }

    @Test
    public void testDefaultAccessible() throws Throwable {
        TestClass testClass = new TestClass(TestClassWithDefaultParameterSetList.class);
        List<Runner> runners = ParameterizedRunner.createRunners(testClass);
        Assert.assertEquals(runners.size(), 1);
        Map<String, List<ParameterSet>> generatedMap =
                ParameterizedRunner.generateMethodParameterMap(testClass);
        Assert.assertEquals(generatedMap.keySet().size(), 1);
        Assert.assertTrue(generatedMap.keySet().contains("A"));
        Assert.assertEquals(generatedMap.get("A").size(), 1);
    }

    @Test(expected = ParameterizedRunner.IllegalParameterArgumentException.class)
    public void testUnequalWidthParameterSetList() {
        List<ParameterSet> paramList = new ArrayList<>();
        paramList.add(new ParameterSet().value(1, 2));
        paramList.add(new ParameterSet().value(3, 4, 5));
        ParameterizedRunner.validateWidth(paramList);
    }

    @Test(expected = ParameterizedRunner.IllegalParameterArgumentException.class)
    public void testUnequalWidthParameterSetListWithNull() {
        List<ParameterSet> paramList = new ArrayList<>();
        paramList.add(new ParameterSet().value(null));
        paramList.add(new ParameterSet().value(1, 2));
        ParameterizedRunner.validateWidth(paramList);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBadClassWithNonListParameters() throws Throwable {
        ParameterizedRunner runner =
                new ParameterizedRunner(BadTestClassWithNonListParameters.class);
    }

    @Test(expected = IllegalParameterArgumentException.class)
    public void testBadClassWithNonStaticParameterSetList() throws Throwable {
        ParameterizedRunner runner =
                new ParameterizedRunner(BadTestClassWithNonStaticParameterSetList.class);
    }

    @Test(expected = AssertionError.class)
    public void testBadClassWithMissingMethodParameter() throws Throwable {
        ParameterizedRunner runner =
                new ParameterizedRunner(BadTestClassWithMissingMethodParameter.class);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testBadClassWithoutNeedForParameterization() throws Throwable {
        ParameterizedRunner runner =
                new ParameterizedRunner(BadTestClassWithoutNeedForParameterization.class);
    }

    @Test(expected = Exception.class)
    public void testBadClassWithMoreThanOneConstructor() throws Throwable {
        ParameterizedRunner runner =
                new ParameterizedRunner(BadTestClassWithMoreThanOneConstructor.class);
    }
}
