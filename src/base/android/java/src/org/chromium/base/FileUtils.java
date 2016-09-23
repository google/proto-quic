// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.content.Context;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * Helper methods for dealing with Files.
 */
public class FileUtils {
    private static final String TAG = "FileUtils";

    /**
     * Delete the given File and (if it's a directory) everything within it.
     */
    public static void recursivelyDeleteFile(File currentFile) {
        assert !ThreadUtils.runningOnUiThread();
        if (currentFile.isDirectory()) {
            File[] files = currentFile.listFiles();
            if (files != null) {
                for (File file : files) {
                    recursivelyDeleteFile(file);
                }
            }
        }

        if (!currentFile.delete()) Log.e(TAG, "Failed to delete: " + currentFile);
    }

    /**
     * Delete the given files or directories by calling {@link #recursivelyDeleteFile(File)}.
     * @param files The files to delete.
     */
    public static void batchDeleteFiles(List<File> files) {
        assert !ThreadUtils.runningOnUiThread();

        for (File file : files) {
            if (file.exists()) recursivelyDeleteFile(file);
        }
    }

    /**
     * Extracts an asset from the app's APK to a file.
     * @param context
     * @param assetName Name of the asset to extract.
     * @param dest File to extract the asset to.
     * @return true on success.
     */
    public static boolean extractAsset(Context context, String assetName, File dest) {
        InputStream inputStream = null;
        OutputStream outputStream = null;
        try {
            inputStream = context.getAssets().open(assetName);
            outputStream = new BufferedOutputStream(new FileOutputStream(dest));
            byte[] buffer = new byte[8192];
            int c;
            while ((c = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, c);
            }
            inputStream.close();
            outputStream.close();
            return true;
        } catch (IOException e) {
            if (inputStream != null) {
                try {
                    inputStream.close();
                } catch (IOException ex) {
                }
            }
            if (outputStream != null) {
                try {
                    outputStream.close();
                } catch (IOException ex) {
                }
            }
        }
        return false;
    }
}
