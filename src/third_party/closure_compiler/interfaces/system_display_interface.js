// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file was generated by:
//   ./tools/json_schema_compiler/compiler.py.

// This was modified to replace System.display with SystemDisplay.

/** @fileoverview Interface for system.display that can be overriden. */

assertNotReached('Interface file for Closure Compiler should not be executed.');

/** @interface */
function SystemDisplay() {}

SystemDisplay.prototype = {
  /**
   * Get the information of all attached display devices.
   * @param {function(!Array<!chrome.system.display.DisplayUnitInfo>):void}
   *     callback
   * @see https://developer.chrome.com/extensions/system.display#method-getInfo
   */
  getInfo: assertNotReached,

  /**
   * Updates the properties for the display specified by |id|, according to the
   * information provided in |info|. On failure, $(ref:runtime.lastError) will
   * be set. NOTE: This is only available to Chrome OS Kiosk apps and Web UI.
   * @param {string} id The display's unique identifier.
   * @param {!chrome.system.display.DisplayProperties} info The information
   *     about display properties that should be changed.     A property will be
   *     changed only if a new value for it is specified in     |info|.
   * @param {function():void=} callback Empty function called when the function
   *     finishes. To find out     whether the function succeeded,
   *     $(ref:runtime.lastError) should be     queried.
   * @see https://developer.chrome.com/extensions/system.display#method-setDisplayProperties
   */
  setDisplayProperties: assertNotReached,

  /**
   * Set the layout for all displays. Any display not included will use the
   * default layout. If a layout would overlap or be otherwise invalid it will
   * be adjusted to a valid layout. After layout is resolved, an
   * onDisplayChanged event will be triggered.
   * @param {!Array<!chrome.system.display.DisplayLayout>} layouts
   * @see https://developer.chrome.com/extensions/system.display#method-setDisplayLayout
   */
  setDisplayLayout: assertNotReached,

  /**
   * Enables/disables the unified desktop feature. Note that this simply enables
   * the feature, but will not change the actual desktop mode. (That is, if the
   * desktop is in mirror mode, it will stay in mirror mode) NOTE: This is only
   * available to Chrome OS Kiosk apps and Web UI.
   * @param {boolean} enabled True if unified desktop should be enabled.
   * @see https://developer.chrome.com/extensions/system.display#method-enableUnifiedDesktop
   */
  enableUnifiedDesktop: assertNotReached,

  /**
   * Starts overscan calibration for a display. This will show an overlay on the
   * screen indicating the current overscan insets. If overscan calibration for
   * display |id| is in progress this will reset calibration.
   * @param {string} id The display's unique identifier.
   * @see https://developer.chrome.com/extensions/system.display#method-overscanCalibrationStart
   */
  overscanCalibrationStart: assertNotReached,

  /**
   * Adjusts the current overscan insets for a display. Typically this should
   * etiher move the display along an axis (e.g. left+right have the same value)
   * or scale it along an axis (e.g. top+bottom have opposite values). Each
   * Adjust call is cumulative with previous calls since Start.
   * @param {string} id The display's unique identifier.
   * @param {!chrome.system.display.Insets} delta The amount to change the
   *     overscan insets.
   * @see https://developer.chrome.com/extensions/system.display#method-overscanCalibrationAdjust
   */
  overscanCalibrationAdjust: assertNotReached,

  /**
   * Resets the overscan insets for a display to the last saved value (i.e
   * before Start was called).
   * @param {string} id The display's unique identifier.
   * @see https://developer.chrome.com/extensions/system.display#method-overscanCalibrationReset
   */
  overscanCalibrationReset: assertNotReached,

  /**
   * Complete overscan adjustments for a display  by saving the current values
   * and hiding the overlay.
   * @param {string} id The display's unique identifier.
   * @see https://developer.chrome.com/extensions/system.display#method-overscanCalibrationComplete
   */
  overscanCalibrationComplete: assertNotReached,

  /**
   * Starts native touch calibration for a display. This will show an overlay on
   * the screen and initialize the UX for touch calibration. If another native
   * touch calibration is already in progress this will throw an error.
   * @param {string} id The display's unique identifier.
   * @see https://developer.chrome.com/extensions/system.display#method-showNativeTouchCalibration
   */
  showNativeTouchCalibration: assertNotReached,

  /**
   * Starts custom touch calibration for a display. This should be called when
   * using a custom UX for collecting calibration data. If another touch
   * calibration is already in progress this will throw an error.
   * @param {string} id The display's unique identifier.
   * @see https://developer.chrome.com/extensions/system.display#method-startCustomTouchCalibration
   */
  startCustomTouchCalibration: assertNotReached,

  /**
   * Sets the touch calibration pairs for a display. These |pairs| would be used
   * to calibrate the touch screen for display with |id| called in
   * startCustomTouchCalibration(). Always call |startCustomTouchCalibration|
   * before calling this method. If another touch calibration is already in
   * progress this will throw an error.
   * @param {!chrome.system.display.TouchCalibrationPairQuad} pairs The pairs of
   *     point used to calibrate the display.
   * @param {!chrome.system.display.Bounds} bounds Bounds of the display when
   *     the touch calibration was performed.     |bounds.left| and |bounds.top|
   *     values are ignored.
   * @see https://developer.chrome.com/extensions/system.display#method-completeCustomTouchCalibration
   */
  completeCustomTouchCalibration: assertNotReached,

  /**
   * Resets the touch calibration for the display and removes the saved
   * calibration data.
   * @param {string} id The display's unique identifier.
   * @see https://developer.chrome.com/extensions/system.display#method-clearTouchCalibration
   */
  clearTouchCalibration: assertNotReached,
};

/**
 * Fired when anything changes to the display configuration.
 * @type {!ChromeEvent}
 * @see https://developer.chrome.com/extensions/system.display#event-onDisplayChanged
 */
SystemDisplay.prototype.onDisplayChanged;
