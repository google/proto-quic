// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file contains forward declarations for items in later SDKs than the
// default one with which Chromium is built (currently 10.10).
// If you call any function from this header, be sure to check at runtime for
// respondsToSelector: before calling these functions (else your code will crash
// on older OS X versions that chrome still supports).

#ifndef BASE_MAC_SDK_FORWARD_DECLARATIONS_H_
#define BASE_MAC_SDK_FORWARD_DECLARATIONS_H_

#import <AppKit/AppKit.h>
#import <CoreBluetooth/CoreBluetooth.h>
#import <CoreWLAN/CoreWLAN.h>
#import <ImageCaptureCore/ImageCaptureCore.h>
#import <IOBluetooth/IOBluetooth.h>
#include <stdint.h>

#include "base/base_export.h"

// ----------------------------------------------------------------------------
// Define typedefs, enums, and protocols not available in the version of the
// OSX SDK being compiled against.
// ----------------------------------------------------------------------------

#if !defined(MAC_OS_X_VERSION_10_11) || \
    MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_11

enum {
  NSPressureBehaviorUnknown = -1,
  NSPressureBehaviorPrimaryDefault = 0,
  NSPressureBehaviorPrimaryClick = 1,
  NSPressureBehaviorPrimaryGeneric = 2,
  NSPressureBehaviorPrimaryAccelerator = 3,
  NSPressureBehaviorPrimaryDeepClick = 5,
  NSPressureBehaviorPrimaryDeepDrag = 6
};
typedef NSInteger NSPressureBehavior;

@interface NSPressureConfiguration : NSObject
- (instancetype)initWithPressureBehavior:(NSPressureBehavior)pressureBehavior;
@end

enum {
  NSSpringLoadingHighlightNone = 0,
  NSSpringLoadingHighlightStandard,
  NSSpringLoadingHighlightEmphasized
};
typedef NSUInteger NSSpringLoadingHighlight;

#endif  // MAC_OS_X_VERSION_10_11

#if !defined(MAC_OS_X_VERSION_10_12) || \
    MAC_OS_X_VERSION_MAX_ALLOWED < MAC_OS_X_VERSION_10_12

// The protocol was formalized by the 10.12 SDK, but it was informally used
// before.
@protocol CAAnimationDelegate
- (void)animationDidStart:(CAAnimation*)animation;
- (void)animationDidStop:(CAAnimation*)animation finished:(BOOL)finished;
@end

@protocol CALayerDelegate
@end

#endif  // MAC_OS_X_VERSION_10_12

// ----------------------------------------------------------------------------
// Define NSStrings only available in newer versions of the OSX SDK to force
// them to be statically linked.
// ----------------------------------------------------------------------------

extern "C" {
#if !defined(MAC_OS_X_VERSION_10_10) || \
    MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_10
BASE_EXPORT extern NSString* const NSUserActivityTypeBrowsingWeb;
BASE_EXPORT extern NSString* const NSAppearanceNameVibrantDark;
BASE_EXPORT extern NSString* const NSAppearanceNameVibrantLight;
#endif  // MAC_OS_X_VERSION_10_10
}  // extern "C"

// ----------------------------------------------------------------------------
// If compiling against an older version of the OSX SDK, declare classes and
// functions that are available in newer versions of the OSX SDK. If compiling
// against a newer version of the OSX SDK, redeclare those same classes and
// functions to suppress -Wpartial-availability warnings.
// ----------------------------------------------------------------------------

// Once Chrome no longer supports OSX 10.9, everything within this preprocessor
// block can be removed.
#if !defined(MAC_OS_X_VERSION_10_10) || \
    MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_10

@interface NSUserActivity (YosemiteSDK)
@property(readonly, copy) NSString* activityType;
@property(copy) NSDictionary* userInfo;
@property(copy) NSURL* webpageURL;
- (instancetype)initWithActivityType:(NSString*)activityType;
- (void)becomeCurrent;
- (void)invalidate;
@end

@interface CBUUID (YosemiteSDK)
- (NSString*)UUIDString;
@end

@interface NSViewController (YosemiteSDK)
- (void)viewDidLoad;
@end

@interface NSWindow (YosemiteSDK)
- (void)setTitlebarAppearsTransparent:(BOOL)flag;
@end

@interface NSProcessInfo (YosemiteSDK)
@property(readonly) NSOperatingSystemVersion operatingSystemVersion;
@end

@interface NSLayoutConstraint (YosemiteSDK)
@property(getter=isActive) BOOL active;
@end

@interface NSVisualEffectView (YosemiteSDK)
- (void)setState:(NSVisualEffectState)state;
@end

@class NSVisualEffectView;

#endif  // MAC_OS_X_VERSION_10_10

// Once Chrome no longer supports OSX 10.10.2, everything within this
// preprocessor block can be removed.
#if !defined(MAC_OS_X_VERSION_10_10_3) || \
    MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_10_3

@interface NSEvent (YosemiteSDK)
@property(readonly) NSInteger stage;
@end

@interface NSView (YosemiteSDK)
- (void)setPressureConfiguration:(NSPressureConfiguration*)aConfiguration;
@end

#endif  // MAC_OS_X_VERSION_10_10

// Once Chrome no longer supports OSX 10.10, everything within this
// preprocessor block can be removed.
#if !defined(MAC_OS_X_VERSION_10_11) || \
    MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_11

@class NSLayoutXAxisAnchor;
@class NSLayoutYAxisAnchor;

@interface NSView (ElCapitanSDK)
@property(readonly, strong) NSLayoutXAxisAnchor* leftAnchor;
@property(readonly, strong) NSLayoutXAxisAnchor* rightAnchor;
@property(readonly, strong) NSLayoutYAxisAnchor* bottomAnchor;
@end

@interface NSWindow (ElCapitanSDK)
- (void)performWindowDragWithEvent:(NSEvent*)event;
@end

#endif  // MAC_OS_X_VERSION_10_11

// Once Chrome no longer supports OSX 10.11, everything within this
// preprocessor block can be removed.
#if !defined(MAC_OS_X_VERSION_10_12) || \
    MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_12

@interface NSWindow (SierraSDK)
@property(class) BOOL allowsAutomaticWindowTabbing;
@end

#endif  // MAC_OS_X_VERSION_10_12

// Once Chrome no longer supports OSX 10.12.0, everything within this
// preprocessor block can be removed.
#if !defined(MAC_OS_X_VERSION_10_12_1) || \
    MAC_OS_X_VERSION_MIN_REQUIRED < MAC_OS_X_VERSION_10_12_1

@interface NSButton (SierraPointOneSDK)
@property(copy) NSColor* bezelColor;
+ (instancetype)buttonWithTitle:(NSString*)title
                         target:(id)target
                         action:(SEL)action;
@end

#endif  // MAC_OS_X_VERSION_10_12_1

// ----------------------------------------------------------------------------
// The symbol for kCWSSIDDidChangeNotification is available in the
// CoreWLAN.framework for OSX versions 10.6 through 10.10. The symbol is not
// declared in the OSX 10.9+ SDK, so when compiling against an OSX 10.9+ SDK,
// declare the symbol.
// ----------------------------------------------------------------------------
BASE_EXPORT extern "C" NSString* const kCWSSIDDidChangeNotification;

#endif  // BASE_MAC_SDK_FORWARD_DECLARATIONS_H_
