// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.params;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotations for Parameterized Tests
 */
public class ParameterAnnotations {
    /**
     * Annotation for test methods to indicate associated List<ParameterSet>
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    public @interface UseMethodParameter {
        String value();
    }

    /**
     * Annotation for static field of a `List<ParameterSet>` for entire test class
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.FIELD)
    public @interface ClassParameter {}

    /**
     * Annotation for static field of a `List<ParameterSet>` for certain test methods
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.FIELD)
    public @interface MethodParameter {
        String value();
    }

    /**
     * Annotation for static field of a `List<ParameterSet>` of TestRule
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.FIELD)
    public @interface RuleParameter {}

    /**
     * Annotation for test class, it specifies which ParameterizeRunnerDelegate to use.
     *
     * The default ParameterizedRunnerDelegate is BaseJUnit4RunnerDelegate.class
     */
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.TYPE)
    public @interface UseRunnerDelegate {
        Class<? extends ParameterizedRunnerDelegate> value();
    }
}
