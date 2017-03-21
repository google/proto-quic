// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.testing.local;

import org.robolectric.annotation.Config;
import org.robolectric.internal.ManifestFactory;
import org.robolectric.internal.ManifestIdentifier;
import org.robolectric.manifest.AndroidManifest;

// TODO(mikecase): Add support for specifying the AndroidManifest for
// Robolectric tests.

/**
 * Class that manages passing Android manifest information to Robolectric.
 */
public class GNManifestFactory implements ManifestFactory {
    private static final String DEFAULT_PACKAGE_NAME = "org.robolectric.default";

    @Override
    public ManifestIdentifier identify(Config config) {
        if (!config.manifest().equals(Config.NONE)) {
            throw new RuntimeException("Specifying custom manifest not currently supported. "
                    + "Please use annotation @Config(manifest = Config.NONE) on Robolectric tests "
                    + "for the time being.");
        }
        return new ManifestIdentifier(null, null, null, config.packageName(), null);
    }

    @Override
    public AndroidManifest create(ManifestIdentifier manifestIdentifier) {
        String packageName = manifestIdentifier.getPackageName();
        if (packageName == null || packageName.equals("")) {
            packageName = DEFAULT_PACKAGE_NAME;
        }

        return new AndroidManifest(null, null, null, packageName);
    }
}
