// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.content.ContentResolver;
import android.content.Context;
import android.content.res.AssetFileDescriptor;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.provider.DocumentsContract;
import android.util.Log;
import android.webkit.MimeTypeMap;

import org.chromium.base.annotations.CalledByNative;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;

/**
 * This class provides methods to access content URI schemes.
 */
public abstract class ContentUriUtils {
    private static final String TAG = "ContentUriUtils";
    private static FileProviderUtil sFileProviderUtil;

    // Guards access to sFileProviderUtil.
    private static final Object sLock = new Object();

    /**
     * Provides functionality to translate a file into a content URI for use
     * with a content provider.
     */
    public interface FileProviderUtil {
        /**
         * Generate a content URI from the given file.
         * @param context Application context.
         * @param file The file to be translated.
         */
        Uri getContentUriFromFile(Context context, File file);
    }

    // Prevent instantiation.
    private ContentUriUtils() {}

    public static void setFileProviderUtil(FileProviderUtil util) {
        synchronized (sLock) {
            sFileProviderUtil = util;
        }
    }

    public static Uri getContentUriFromFile(Context context, File file) {
        synchronized (sLock) {
            if (sFileProviderUtil != null) {
                return sFileProviderUtil.getContentUriFromFile(context, file);
            }
        }
        return null;
    }

    /**
     * Opens the content URI for reading, and returns the file descriptor to
     * the caller. The caller is responsible for closing the file desciptor.
     *
     * @param context {@link Context} in interest
     * @param uriString the content URI to open
     * @return file desciptor upon success, or -1 otherwise.
     */
    @CalledByNative
    public static int openContentUriForRead(Context context, String uriString) {
        AssetFileDescriptor afd = getAssetFileDescriptor(context, uriString);
        if (afd != null) {
            return afd.getParcelFileDescriptor().detachFd();
        }
        return -1;
    }

    /**
     * Check whether a content URI exists.
     *
     * @param context {@link Context} in interest.
     * @param uriString the content URI to query.
     * @return true if the URI exists, or false otherwise.
     */
    @CalledByNative
    public static boolean contentUriExists(Context context, String uriString) {
        AssetFileDescriptor asf = null;
        try {
            asf = getAssetFileDescriptor(context, uriString);
            return asf != null;
        } finally {
            // Do not use StreamUtil.closeQuietly here, as AssetFileDescriptor
            // does not implement Closeable until KitKat.
            if (asf != null) {
                try {
                    asf.close();
                } catch (IOException e) {
                    // Closing quietly.
                }
            }
        }
    }

    /**
     * Retrieve the MIME type for the content URI.
     *
     * @param context {@link Context} in interest.
     * @param uriString the content URI to look up.
     * @return MIME type or null if the input params are empty or invalid.
     */
    @CalledByNative
    public static String getMimeType(Context context, String uriString) {
        ContentResolver resolver = context.getContentResolver();
        Uri uri = Uri.parse(uriString);
        if (isVirtualDocument(uri, context)) {
            String[] streamTypes = resolver.getStreamTypes(uri, "*/*");
            return (streamTypes != null && streamTypes.length > 0) ? streamTypes[0] : null;
        }
        return resolver.getType(uri);
    }

    /**
     * Helper method to open a content URI and returns the ParcelFileDescriptor.
     *
     * @param context {@link Context} in interest.
     * @param uriString the content URI to open.
     * @return AssetFileDescriptor of the content URI, or NULL if the file does not exist.
     */
    private static AssetFileDescriptor getAssetFileDescriptor(Context context, String uriString) {
        ContentResolver resolver = context.getContentResolver();
        Uri uri = Uri.parse(uriString);

        try {
            if (isVirtualDocument(uri, context)) {
                String[] streamTypes = resolver.getStreamTypes(uri, "*/*");
                if (streamTypes != null && streamTypes.length > 0) {
                    AssetFileDescriptor afd =
                            resolver.openTypedAssetFileDescriptor(uri, streamTypes[0], null);
                    if (afd.getStartOffset() != 0) {
                        // Do not use StreamUtil.closeQuietly here, as AssetFileDescriptor
                        // does not implement Closeable until KitKat.
                        try {
                            afd.close();
                        } catch (IOException e) {
                            // Closing quietly.
                        }
                        throw new SecurityException("Cannot open files with non-zero offset type.");
                    }
                    return afd;
                }
            } else {
                ParcelFileDescriptor pfd = resolver.openFileDescriptor(uri, "r");
                if (pfd != null) {
                    return new AssetFileDescriptor(pfd, 0, AssetFileDescriptor.UNKNOWN_LENGTH);
                }
            }
        } catch (FileNotFoundException e) {
            Log.w(TAG, "Cannot find content uri: " + uriString, e);
        } catch (SecurityException e) {
            Log.w(TAG, "Cannot open content uri: " + uriString, e);
        } catch (IllegalArgumentException e) {
            Log.w(TAG, "Unknown content uri: " + uriString, e);
        } catch (IllegalStateException e) {
            Log.w(TAG, "Unknown content uri: " + uriString, e);
        }

        return null;
    }

    /**
     * Method to resolve the display name of a content URI.
     *
     * @param uri the content URI to be resolved.
     * @param context {@link Context} in interest.
     * @param columnField the column field to query.
     * @return the display name of the @code uri if present in the database
     *  or an empty string otherwise.
     */
    public static String getDisplayName(Uri uri, Context context, String columnField) {
        if (uri == null) return "";
        ContentResolver contentResolver = context.getContentResolver();
        Cursor cursor = null;
        try {
            cursor = contentResolver.query(uri, null, null, null, null);

            if (cursor != null && cursor.getCount() >= 1) {
                cursor.moveToFirst();
                int displayNameIndex = cursor.getColumnIndex(columnField);
                if (displayNameIndex == -1) {
                    return "";
                }
                String displayName = cursor.getString(displayNameIndex);
                // For Virtual documents, try to modify the file extension so it's compatible
                // with the alternative MIME type.
                if (hasVirtualFlag(cursor)) {
                    String[] mimeTypes = contentResolver.getStreamTypes(uri, "*/*");
                    if (mimeTypes != null && mimeTypes.length > 0) {
                        String ext =
                                MimeTypeMap.getSingleton().getExtensionFromMimeType(mimeTypes[0]);
                        if (ext != null) {
                            // Just append, it's simpler and more secure than altering an
                            // existing extension.
                            displayName += "." + ext;
                        }
                    }
                }
                return displayName;
            }
        } catch (NullPointerException e) {
            // Some android models don't handle the provider call correctly.
            // see crbug.com/345393
            return "";
        } finally {
            StreamUtil.closeQuietly(cursor);
        }
        return "";
    }

    /**
     * Checks whether the passed Uri represents a virtual document.
     *
     * @param uri the content URI to be resolved.
     * @param contentResolver the content resolver to query.
     * @return True for virtual file, false for any other file.
     */
    private static boolean isVirtualDocument(Uri uri, Context context) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.KITKAT) return false;
        if (uri == null) return false;
        if (!DocumentsContract.isDocumentUri(context, uri)) return false;
        ContentResolver contentResolver = context.getContentResolver();
        Cursor cursor = null;
        try {
            cursor = contentResolver.query(uri, null, null, null, null);

            if (cursor != null && cursor.getCount() >= 1) {
                cursor.moveToFirst();
                return hasVirtualFlag(cursor);
            }
        } catch (NullPointerException e) {
            // Some android models don't handle the provider call correctly.
            // see crbug.com/345393
            return false;
        } finally {
            StreamUtil.closeQuietly(cursor);
        }
        return false;
    }

    /**
     * Checks whether the passed cursor for a document has a virtual document flag.
     *
     * The called must close the passed cursor.
     *
     * @param cursor Cursor with COLUMN_FLAGS.
     * @return True for virtual file, false for any other file.
     */
    private static boolean hasVirtualFlag(Cursor cursor) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) return false;
        int index = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_FLAGS);
        if (index > -1) {
            return (cursor.getLong(index) & DocumentsContract.Document.FLAG_VIRTUAL_DOCUMENT) != 0;
        }
        return false;
    }
}
