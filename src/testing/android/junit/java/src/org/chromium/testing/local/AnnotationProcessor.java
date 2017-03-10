// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.testing.local;

import org.junit.rules.ExternalResource;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;

import java.lang.annotation.Annotation;

/**
 * Test rule that is activated when a test has a specific annotation. It allows to run some code
 * before the test (and the {@link org.junit.Before}) runs, and guarantees to also run code after.
 *
 * Usage:
 *
 * <pre>
 * public class Test {
 *    &#64;Rule
 *    public AnnotationProcessor<Foo> rule = new AnnotationProcessor(Foo.class) {
 *          &#64;Override
 *          protected void before() { ... }
 *
 *          &#64;Override
 *          protected void after() { ... }
 *    };
 *
 *    &#64;Test
 *    &#64;Foo
 *    public void myTest() { ... }
 * }
 * </pre>
 *
 * @param <T> type of the annotation to match on the test case.
 */
public abstract class AnnotationProcessor<T extends Annotation> extends ExternalResource {
    private final Class<T> mAnnotationClass;
    private Description mTestDescription;
    private T mAnnotation;

    public AnnotationProcessor(Class<T> annotationClass) {
        mAnnotationClass = annotationClass;
    }

    @Override
    public Statement apply(Statement base, Description description) {
        mTestDescription = description;
        mAnnotation = getAnnotation(description);
        if (mAnnotation == null) return base;

        // Return the wrapped statement to execute before() and after().
        return super.apply(base, description);
    }

    /** @return {@link Description} of the current test. */
    protected Description getTestDescription() {
        return mTestDescription;
    }

    /** @return the annotation that caused the test to be processed. */
    protected T getAnnotation() {
        return mAnnotation;
    }

    private T getAnnotation(Description description) {
        T annotation = description.getAnnotation(mAnnotationClass);
        if (annotation != null) return annotation;

        annotation = description.getTestClass().getAnnotation(mAnnotationClass);
        return annotation;
    }
}
