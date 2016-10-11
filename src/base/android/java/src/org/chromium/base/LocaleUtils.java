// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import org.chromium.base.annotations.CalledByNative;

import java.util.Locale;

/**
 * This class provides the locale related methods.
 */
public class LocaleUtils {
    /**
     * Guards this class from being instantiated.
     */
    private LocaleUtils() {
    }

    /**
     * @return The string for the given locale, translating Android deprecated language codes
     *         into the modern ones used by Chromium.
     */
    public static String getLocale(Locale locale) {
        String language = getLanguage(locale);
        String country = locale.getCountry();

        return country.isEmpty() ? language : language + "-" + country;
    }

    /**
     * @return The language for the given locale, translating Android deprecated languages codes
     *         into modern ones used by Chromium.
     */
    public static String getLanguage(Locale locale) {
        String language = locale.getLanguage();

        // Android uses deprecated lanuages codes for Hebrew and Indonesian but Chromium uses the
        // updated codes. Also, Android uses "tl" while Chromium uses "fil" for Tagalog/Filipino.
        // So apply a mapping.
        // See http://developer.android.com/reference/java/util/Locale.html
        if ("iw".equals(language)) {
            language = "he";
        } else if ("in".equals(language)) {
            language = "id";
        } else if ("tl".equals(language)) {
            language = "fil";
        }
        return language;
    }

    /**
     * @return The default locale, translating Android deprecated language codes into the modern
     *         ones used by Chromium.
     */
    @CalledByNative
    public static String getDefaultLocale() {
        return getLocale(Locale.getDefault());
    }

    /**
     * @return The default country code set during install.
     */
    @CalledByNative
    private static String getDefaultCountryCode() {
        CommandLine commandLine = CommandLine.getInstance();
        return commandLine.hasSwitch(BaseSwitches.DEFAULT_COUNTRY_CODE_AT_INSTALL)
                ? commandLine.getSwitchValue(BaseSwitches.DEFAULT_COUNTRY_CODE_AT_INSTALL)
                : Locale.getDefault().getCountry();
    }

}
