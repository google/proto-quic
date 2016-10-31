// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

import org.chromium.testing.local.LocalRobolectricTestRunner;

import java.util.Locale;

/** Unit tests for the LocaleUtils class. */
@RunWith(LocalRobolectricTestRunner.class)
@Config(manifest = Config.NONE)
public class LocaleUtilsTest {
    // TODO(yirui): update tests for LocaleList once SDK Roll is completed.

    // This is also a part of test for toLanguageTag when API level is equal or higher than 24
    @Test
    public void testGetUpdatedLanguageForChromium() {
        String language = "en";
        String updatedLanguage = LocaleUtils.getUpdatedLanguageForChromium(language);
        Assert.assertEquals(language, updatedLanguage);

        language = "iw";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForChromium(language);
        Assert.assertEquals("he", updatedLanguage);

        language = "ji";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForChromium(language);
        Assert.assertEquals("yi", updatedLanguage);

        language = "in";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForChromium(language);
        Assert.assertEquals("id", updatedLanguage);

        language = "tl";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForChromium(language);
        Assert.assertEquals("fil", updatedLanguage);
    }

    // This is also a part of test for forLanguageTag when API level is equal or higher than 21
    @Test
    public void testGetUpdatedLanguageForAndroid() {
        String language = "en";
        String updatedLanguage = LocaleUtils.getUpdatedLanguageForAndroid(language);
        Assert.assertEquals(language, updatedLanguage);

        language = "und";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForAndroid(language);
        Assert.assertEquals("", updatedLanguage);

        language = "fil";
        updatedLanguage = LocaleUtils.getUpdatedLanguageForAndroid(language);
        Assert.assertEquals("tl", updatedLanguage);
    }

    // Test for toLanguageTag when API level is lower than 24
    @Test
    public void testToLanguageTagCompat() {
        Locale locale = new Locale("en", "US");
        String localeString = LocaleUtils.toLanguageTagCompat(locale);
        Assert.assertEquals("en-US", localeString);

        locale = new Locale("jp");
        localeString = LocaleUtils.toLanguageTagCompat(locale);
        Assert.assertEquals("jp", localeString);

        locale = new Locale("mas");
        localeString = LocaleUtils.toLanguageTagCompat(locale);
        Assert.assertEquals("mas", localeString);

        locale = new Locale("es", "005");
        localeString = LocaleUtils.toLanguageTagCompat(locale);
        Assert.assertEquals("es-005", localeString);

        locale = new Locale("iw");
        localeString = LocaleUtils.toLanguageTagCompat(locale);
        Assert.assertEquals("he", localeString);

        locale = new Locale("ji");
        localeString = LocaleUtils.toLanguageTagCompat(locale);
        Assert.assertEquals("yi", localeString);

        locale = new Locale("in", "ID");
        localeString = LocaleUtils.toLanguageTagCompat(locale);
        Assert.assertEquals("id-ID", localeString);

        locale = new Locale("tl", "PH");
        localeString = LocaleUtils.toLanguageTagCompat(locale);
        Assert.assertEquals("fil-PH", localeString);

        locale = new Locale("no", "NO", "NY");
        localeString = LocaleUtils.toLanguageTagCompat(locale);
        Assert.assertEquals("nn-NO", localeString);
    }

    // Test for forLanguageTag when API level is lower than 21
    @Test
    public void testForLanguageTagCompat() {
        String languageTag = "";
        Locale locale = new Locale("");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "und";
        locale = new Locale("");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "en";
        locale = new Locale("en");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "mas";
        locale = new Locale("mas");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "en-GB";
        locale = new Locale("en", "GB");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "es-419";
        locale = new Locale("es", "419");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        // Tests if updated Chromium language code and deprecated language code
        // are pointing to the same Locale Object.
        languageTag = "he";
        locale = new Locale("iw");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "iw";
        locale = new Locale("he");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "ji";
        locale = new Locale("yi");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "yi";
        locale = new Locale("ji");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "in";
        locale = new Locale("id");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "id";
        locale = new Locale("in");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        // Tests for Tagalog/Filipino if updated Chromium language code and
        // language code are pointing to the same Locale Object.
        languageTag = "tl";
        locale = new Locale("tl");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "fil";
        locale = new Locale("tl");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        // Test with invalid inputs.
        languageTag = "notValidLanguage";
        locale = new Locale("");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));

        languageTag = "en-notValidCountry";
        locale = new Locale("en");
        Assert.assertEquals(locale, LocaleUtils.forLanguageTagCompat(languageTag));
    }
}
