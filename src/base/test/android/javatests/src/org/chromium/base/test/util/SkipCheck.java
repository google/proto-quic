// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.util;

import junit.framework.TestCase;

import org.chromium.base.Log;

import java.lang.annotation.Annotation;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;

/**
 * Check whether a test case should be skipped.
 */
public abstract class SkipCheck {

    private static final String TAG = "base_test";

    /**
     *
     * Checks whether the given test case should be skipped.
     *
     * @param testCase The test case to check.
     * @return Whether the test case should be skipped.
     */
    public abstract boolean shouldSkip(TestCase testCase);

    protected static Method getTestMethod(TestCase testCase) {
        try {
            return testCase.getClass().getMethod(testCase.getName(), (Class[]) null);
        } catch (NoSuchMethodException e) {
            Log.e(TAG, "Unable to find %s in %s", testCase.getName(),
                    testCase.getClass().getName(), e);
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    protected static <T extends Annotation> List<T> getAnnotations(AnnotatedElement element,
            Class<T> annotationClass) {
        AnnotatedElement parent = (element instanceof Method)
                ? ((Method) element).getDeclaringClass()
                : ((Class) element).getSuperclass();
        List<T> annotations = (parent == null)
                ? new ArrayList<T>()
                : getAnnotations(parent, annotationClass);
        Annotation[] allAnnotations = element.getAnnotations();
        for (Annotation a : allAnnotations) {
            if (annotationClass.isInstance(a)) {
                annotations.add((T) a);
            }
        }
        return annotations;
    }
}

