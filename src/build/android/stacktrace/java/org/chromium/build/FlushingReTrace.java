// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.build;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;

import proguard.retrace.ReTrace;

/**
 * A wrapper around ReTrace that:
 *  1. Hardcodes a more useful line regular expression
 *  2. Disables output buffering
 */
public class FlushingReTrace {
    // This regex is based on the one from:
    // http://proguard.sourceforge.net/manual/retrace/usage.html.
    // But with the "at" part changed to "(?::|\bat)", to account for lines like:
    //     06-22 13:58:02.895  4674  4674 E THREAD_STATE:     bLA.a(PG:173)
    // Normal stack trace lines look like:
    // java.lang.RuntimeException: Intentional Java Crash
    //     at org.chromium.chrome.browser.tab.Tab.handleJavaCrash(Tab.java:682)
    //     at org.chromium.chrome.browser.tab.Tab.loadUrl(Tab.java:644)
    private static final String LINE_PARSE_REGEX =
            "(?:.*?(?::|\\bat)\\s+%c\\.%m\\s*\\(%s(?::%l)?\\)\\s*)|(?:(?:.*?[:\"]\\s+)?%c(?::.*)?)";

    public static void main(String[] args) {
        if (args.length != 1) {
            System.err.println("Usage: retrace Foo.apk.map < foo.log > bar.log");
            System.exit(1);
        }

        File mappingFile = new File(args[0]);
        try {
            LineNumberReader reader = new LineNumberReader(
                    new BufferedReader(new InputStreamReader(System.in, "UTF-8")));

            // Enabling autoFlush is the main difference from ReTrace.main().
            boolean autoFlush = true;
            PrintWriter writer =
                    new PrintWriter(new OutputStreamWriter(System.out, "UTF-8"), autoFlush);

            boolean verbose = false;
            new ReTrace(LINE_PARSE_REGEX, verbose, mappingFile).retrace(reader, writer);
        } catch (IOException ex) {
            // Print a verbose stack trace.
            ex.printStackTrace();
            System.exit(1);
        }

        System.exit(0);
    }
}
