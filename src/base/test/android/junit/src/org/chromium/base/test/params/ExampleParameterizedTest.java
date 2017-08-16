// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.params;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.chromium.base.test.params.ParameterAnnotations.ClassParameter;
import org.chromium.base.test.params.ParameterAnnotations.MethodParameter;
import org.chromium.base.test.params.ParameterAnnotations.UseMethodParameter;
import org.chromium.base.test.params.ParameterAnnotations.UseRunnerDelegate;

import java.util.ArrayList;
import java.util.List;

/**
 * Example test that uses ParamRunner
 */
@RunWith(ParameterizedRunner.class)
@UseRunnerDelegate(BlockJUnit4RunnerDelegate.class)
public class ExampleParameterizedTest {
    @ClassParameter
    private static List<ParameterSet> sClassParams = new ArrayList<>();

    static {
        sClassParams.add(new ParameterSet().value("hello", "world").name("HelloWorld"));
        sClassParams.add(new ParameterSet().value("Xxxx", "Yyyy").name("XxxxYyyy"));
        sClassParams.add(new ParameterSet().value("aa", "yy").name("AaYy"));
    }

    @MethodParameter("A")
    private static List<ParameterSet> sMethodParamA = new ArrayList<>();

    static {
        sMethodParamA.add(new ParameterSet().value(1, 2).name("OneTwo"));
        sMethodParamA.add(new ParameterSet().value(2, 3).name("TwoThree"));
        sMethodParamA.add(new ParameterSet().value(3, 4).name("ThreeFour"));
    }

    @MethodParameter("B")
    private static List<ParameterSet> sMethodParamB = new ArrayList<>();

    static {
        sMethodParamB.add(new ParameterSet().value("a", "b").name("Ab"));
        sMethodParamB.add(new ParameterSet().value("b", "c").name("Bc"));
        sMethodParamB.add(new ParameterSet().value("c", "d").name("Cd"));
        sMethodParamB.add(new ParameterSet().value("d", "e").name("De"));
    }

    private String mStringA;
    private String mStringB;

    public ExampleParameterizedTest(String a, String b) {
        mStringA = a;
        mStringB = b;
    }

    @Test
    public void testSimple() {
        Assert.assertEquals(
                "A and B string length aren't equal", mStringA.length(), mStringB.length());
    }

    @Test
    @UseMethodParameter("A")
    public void testWithOnlyA(int intA, int intB) {
        Assert.assertTrue(intA + 1 == intB);
    }

    @Test
    @UseMethodParameter("B")
    public void testWithOnlyB(String a, String b) {
        Assert.assertTrue(a != b);
    }
}
