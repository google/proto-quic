// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base.test.util.parameter;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * The annotation for an individual set of {@link Parameter}s to run on a single test.
 */
@Inherited
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
public @interface ParameterizedTest {
    Parameter[] parameters() default {};

    /**
     * The annotation that contains a set of {@link ParameterizedTest}s to run. A test method
     * is attempted for every set of {@link Parameter}s in each {@link ParameterizedTest}.
     */
    @Inherited
    @Retention(RetentionPolicy.RUNTIME)
    @Target({ElementType.METHOD, ElementType.TYPE})
    @interface Set {
        ParameterizedTest[] tests() default {};
    }
}
