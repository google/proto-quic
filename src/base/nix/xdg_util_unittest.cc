// Copyright (c) 2010 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "base/nix/xdg_util.h"

#include "base/environment.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"

using ::testing::_;
using ::testing::Eq;
using ::testing::Return;
using ::testing::SetArgumentPointee;

namespace base {
namespace nix {

namespace {

class MockEnvironment : public Environment {
 public:
  MOCK_METHOD2(GetVar, bool(StringPiece, std::string* result));
  MOCK_METHOD2(SetVar, bool(StringPiece, const std::string& new_value));
  MOCK_METHOD1(UnSetVar, bool(StringPiece));
};

// Needs to be const char* to make gmock happy.
const char* const kDesktopGnome = "gnome";
const char* const kDesktopGnomeFallback = "gnome-fallback";
const char* const kDesktopMATE = "mate";
const char* const kDesktopKDE4 = "kde4";
const char* const kDesktopKDE = "kde";
const char* const kDesktopXFCE = "xfce";
const char* const kXdgDesktopGNOME = "GNOME";
const char* const kXdgDesktopKDE = "KDE";
const char* const kXdgDesktopUnity = "Unity";
const char* const kKDESessionKDE5 = "5";

const char kDesktopSession[] = "DESKTOP_SESSION";
const char kKDESession[] = "KDE_SESSION_VERSION";
const char kXdgDesktop[] = "XDG_CURRENT_DESKTOP";

}  // namespace

TEST(XDGUtilTest, GetDesktopEnvironmentGnome) {
  MockEnvironment getter;
  EXPECT_CALL(getter, GetVar(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(getter, GetVar(Eq(kDesktopSession), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kDesktopGnome), Return(true)));

  EXPECT_EQ(DESKTOP_ENVIRONMENT_GNOME, GetDesktopEnvironment(&getter));
}

TEST(XDGUtilTest, GetDesktopEnvironmentMATE) {
  MockEnvironment getter;
  EXPECT_CALL(getter, GetVar(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(getter, GetVar(Eq(kDesktopSession), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kDesktopMATE), Return(true)));

  EXPECT_EQ(DESKTOP_ENVIRONMENT_GNOME, GetDesktopEnvironment(&getter));
}

TEST(XDGUtilTest, GetDesktopEnvironmentKDE4) {
  MockEnvironment getter;
  EXPECT_CALL(getter, GetVar(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(getter, GetVar(Eq(kDesktopSession), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kDesktopKDE4), Return(true)));

  EXPECT_EQ(DESKTOP_ENVIRONMENT_KDE4, GetDesktopEnvironment(&getter));
}

TEST(XDGUtilTest, GetDesktopEnvironmentKDE3) {
  MockEnvironment getter;
  EXPECT_CALL(getter, GetVar(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(getter, GetVar(Eq(kDesktopSession), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kDesktopKDE), Return(true)));

  EXPECT_EQ(DESKTOP_ENVIRONMENT_KDE3, GetDesktopEnvironment(&getter));
}

TEST(XDGUtilTest, GetDesktopEnvironmentXFCE) {
  MockEnvironment getter;
  EXPECT_CALL(getter, GetVar(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(getter, GetVar(Eq(kDesktopSession), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kDesktopXFCE), Return(true)));

  EXPECT_EQ(DESKTOP_ENVIRONMENT_XFCE, GetDesktopEnvironment(&getter));
}

TEST(XDGUtilTest, GetXdgDesktopGnome) {
  MockEnvironment getter;
  EXPECT_CALL(getter, GetVar(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(getter, GetVar(Eq(kXdgDesktop), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kXdgDesktopGNOME), Return(true)));

  EXPECT_EQ(DESKTOP_ENVIRONMENT_GNOME, GetDesktopEnvironment(&getter));
}

TEST(XDGUtilTest, GetXdgDesktopGnomeFallback) {
  MockEnvironment getter;
  EXPECT_CALL(getter, GetVar(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(getter, GetVar(Eq(kXdgDesktop), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kXdgDesktopUnity), Return(true)));
  EXPECT_CALL(getter, GetVar(Eq(kDesktopSession), _))
      .WillOnce(
          DoAll(SetArgumentPointee<1>(kDesktopGnomeFallback), Return(true)));

  EXPECT_EQ(DESKTOP_ENVIRONMENT_GNOME, GetDesktopEnvironment(&getter));
}

TEST(XDGUtilTest, GetXdgDesktopKDE5) {
  MockEnvironment getter;
  EXPECT_CALL(getter, GetVar(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(getter, GetVar(Eq(kXdgDesktop), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kXdgDesktopKDE), Return(true)));
  EXPECT_CALL(getter, GetVar(Eq(kKDESession), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kKDESessionKDE5), Return(true)));

  EXPECT_EQ(DESKTOP_ENVIRONMENT_KDE5, GetDesktopEnvironment(&getter));
}

TEST(XDGUtilTest, GetXdgDesktopKDE4) {
  MockEnvironment getter;
  EXPECT_CALL(getter, GetVar(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(getter, GetVar(Eq(kXdgDesktop), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kXdgDesktopKDE), Return(true)));

  EXPECT_EQ(DESKTOP_ENVIRONMENT_KDE4, GetDesktopEnvironment(&getter));
}

TEST(XDGUtilTest, GetXdgDesktopUnity) {
  MockEnvironment getter;
  EXPECT_CALL(getter, GetVar(_, _)).WillRepeatedly(Return(false));
  EXPECT_CALL(getter, GetVar(Eq(kXdgDesktop), _))
      .WillOnce(DoAll(SetArgumentPointee<1>(kXdgDesktopUnity), Return(true)));

  EXPECT_EQ(DESKTOP_ENVIRONMENT_UNITY, GetDesktopEnvironment(&getter));
}

}  // namespace nix
}  // namespace base
