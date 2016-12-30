// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import android.annotation.SuppressLint;
import android.os.Build;
import android.os.LocaleList;
import android.support.test.filters.SmallTest;
import android.test.InstrumentationTestCase;

import org.chromium.base.test.util.MinAndroidSdkLevel;

import java.util.Locale;

/**
 * Tests for the LocaleUtils class.
 */
public class LocaleUtilsTest extends InstrumentationTestCase {
    // This is also a part of test for toLanguageTag when API level is lower than 24
    @SmallTest
    public void testGetUpdatedLanguageForChromium() {
        String language = "en";
        String updatedLanguage = LocaleUtils.getUpdatedLanguageForChromium(language);
        assertEquals(language, updatedLanguage);

        language = "iw";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForChromium(language);
        assertEquals("he", updatedLanguage);

        language = "ji";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForChromium(language);
        assertEquals("yi", updatedLanguage);

        language = "in";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForChromium(language);
        assertEquals("id", updatedLanguage);

        language = "tl";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForChromium(language);
        assertEquals("fil", updatedLanguage);
    }

    // This is also a part of test for toLanguageTags when API level is 24 or higher
    @SmallTest
    @MinAndroidSdkLevel(Build.VERSION_CODES.LOLLIPOP)
    public void testGetUpdatedLocaleForChromium() {
        Locale locale = new Locale("jp");
        Locale updatedLocale = LocaleUtils.getUpdatedLocaleForChromium(locale);
        assertEquals(locale, updatedLocale);

        locale = new Locale("iw");
        updatedLocale = LocaleUtils.getUpdatedLocaleForChromium(locale);
        assertEquals(new Locale("he"), updatedLocale);

        locale = new Locale("ji");
        updatedLocale = LocaleUtils.getUpdatedLocaleForChromium(locale);
        assertEquals(new Locale("yi"), updatedLocale);

        locale = new Locale("in");
        updatedLocale = LocaleUtils.getUpdatedLocaleForChromium(locale);
        assertEquals(new Locale("id"), updatedLocale);

        locale = new Locale("tl");
        updatedLocale = LocaleUtils.getUpdatedLocaleForChromium(locale);
        assertEquals(new Locale("fil"), updatedLocale);
    }

    // This is also a part of test for forLanguageTag when API level is lower than 21
    @SmallTest
    public void testGetUpdatedLanguageForAndroid() {
        String language = "en";
        String updatedLanguage = LocaleUtils.getUpdatedLanguageForAndroid(language);
        assertEquals(language, updatedLanguage);

        language = "und";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForAndroid(language);
        assertEquals("", updatedLanguage);

        language = "fil";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForAndroid(language);
        assertEquals("tl", updatedLanguage);
    }

    // This is also a part of test for forLanguageTag when API level is 21 or higher
    @SmallTest
    @MinAndroidSdkLevel(Build.VERSION_CODES.LOLLIPOP)
    public void testGetUpdatedLocaleForAndroid() {
        Locale locale = new Locale("jp");
        Locale updatedLocale = LocaleUtils.getUpdatedLocaleForAndroid(locale);
        assertEquals(locale, updatedLocale);

        locale = new Locale("und");
        updatedLocale = LocaleUtils.getUpdatedLocaleForAndroid(locale);
        assertEquals(new Locale(""), updatedLocale);

        locale = new Locale("fil");
        updatedLocale = LocaleUtils.getUpdatedLocaleForAndroid(locale);
        assertEquals(new Locale("tl"), updatedLocale);
    }

    // Test for toLanguageTag when API level is lower than 24
    @SmallTest
    public void testToLanguageTag() {
        Locale locale = new Locale("en", "US");
        String localeString = LocaleUtils.toLanguageTag(locale);
        assertEquals("en-US", localeString);

        locale = new Locale("jp");
        localeString = LocaleUtils.toLanguageTag(locale);
        assertEquals("jp", localeString);

        locale = new Locale("mas");
        localeString = LocaleUtils.toLanguageTag(locale);
        assertEquals("mas", localeString);

        locale = new Locale("es", "005");
        localeString = LocaleUtils.toLanguageTag(locale);
        assertEquals("es-005", localeString);

        locale = new Locale("iw");
        localeString = LocaleUtils.toLanguageTag(locale);
        assertEquals("he", localeString);

        locale = new Locale("ji");
        localeString = LocaleUtils.toLanguageTag(locale);
        assertEquals("yi", localeString);

        locale = new Locale("in", "ID");
        localeString = LocaleUtils.toLanguageTag(locale);
        assertEquals("id-ID", localeString);

        locale = new Locale("tl", "PH");
        localeString = LocaleUtils.toLanguageTag(locale);
        assertEquals("fil-PH", localeString);

        locale = new Locale("no", "NO", "NY");
        localeString = LocaleUtils.toLanguageTag(locale);
        assertEquals("nn-NO", localeString);
    }

    // Test for toLanguageTags when API level is 24 or higher
    @SmallTest
    @MinAndroidSdkLevel(Build.VERSION_CODES.N)
    @SuppressLint("NewApi")
    public void testToLanguageTags() {
        Locale locale1 = new Locale("en", "US");
        Locale locale2 = new Locale("es", "005");
        LocaleList localeList = new LocaleList(locale1, locale2);
        String localeString = LocaleUtils.toLanguageTags(localeList);
        assertEquals("en-US,es-005", localeString);

        locale1 = new Locale("jp");
        locale2 = new Locale("mas");
        localeList = new LocaleList(locale1, locale2);
        localeString = LocaleUtils.toLanguageTags(localeList);
        assertEquals("jp,mas", localeString);

        locale1 = new Locale("iw");
        locale2 = new Locale("ji");
        localeList = new LocaleList(locale1, locale2);
        localeString = LocaleUtils.toLanguageTags(localeList);
        assertEquals("he,yi", localeString);

        locale1 = new Locale("in", "ID");
        locale2 = new Locale("tl", "PH");
        localeList = new LocaleList(locale1, locale2);
        localeString = LocaleUtils.toLanguageTags(localeList);
        assertEquals("id-ID,fil-PH", localeString);

        locale1 = new Locale("no", "NO", "NY");
        localeList = new LocaleList(locale1);
        localeString = LocaleUtils.toLanguageTags(localeList);
        assertEquals("nn-NO", localeString);
    }

    // Test for forLanguageTag when API level is lower than 21
    @SmallTest
    public void testForLanguageTagCompat() {
        String languageTag = "";
        Locale locale = new Locale("");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "und";
        locale = new Locale("");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "en";
        locale = new Locale("en");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "mas";
        locale = new Locale("mas");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "en-GB";
        locale = new Locale("en", "GB");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "es-419";
        locale = new Locale("es", "419");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        // Tests if updated Chromium language code and deprecated language code
        // are pointing to the same Locale Object.
        languageTag = "he";
        locale = new Locale("iw");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "iw";
        locale = new Locale("he");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "ji";
        locale = new Locale("yi");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "yi";
        locale = new Locale("ji");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "in";
        locale = new Locale("id");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "id";
        locale = new Locale("in");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        // Tests for Tagalog/Filipino if updated Chromium language code and
        // language code are pointing to the same Locale Object.
        languageTag = "tl";
        locale = new Locale("tl");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "fil";
        locale = new Locale("tl");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        // Test with invalid inputs.
        languageTag = "notValidLanguage";
        locale = new Locale("");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "en-notValidCountry";
        locale = new Locale("en");
        assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));
    }
}
