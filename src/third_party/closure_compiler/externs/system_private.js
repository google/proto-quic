// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/** @fileoverview Externs generated from namespace: systemPrivate */

/**
 * Information about the system update.
 * @typedef {{
 *   state: string,
 *   downloadProgress: number
 * }}
 */
var UpdateStatus;

/**
 * Information about the volume.
 * @typedef {{
 *   volume: number,
 *   isVolumeMuted: boolean
 * }}
 */
var VolumeInfo;

/**
 * Information about a change to the screen brightness.
 * @typedef {{
 *   brightness: number,
 *   userInitiated: boolean
 * }}
 */
var BrightnessChangeInfo;

/**
 * @const
 */
chrome.systemPrivate = {};

/**
 * Returns whether the incognito mode is enabled, disabled or forced
 * @param {Function} callback Called with the result.
 */
chrome.systemPrivate.getIncognitoModeAvailability = function(callback) {};

/**
 * Gets information about the system update.
 * @param {Function} callback
 */
chrome.systemPrivate.getUpdateStatus = function(callback) {};

/**
 * Gets Chrome's API key to use for requests to Google services.
 * @param {Function} callback
 */
chrome.systemPrivate.getApiKey = function(callback) {};

/** @type {!ChromeEvent} */
chrome.systemPrivate.onVolumeChanged;

/** @type {!ChromeEvent} */
chrome.systemPrivate.onBrightnessChanged;

/** @type {!ChromeEvent} */
chrome.systemPrivate.onScreenUnlocked;

/** @type {!ChromeEvent} */
chrome.systemPrivate.onWokeUp;


