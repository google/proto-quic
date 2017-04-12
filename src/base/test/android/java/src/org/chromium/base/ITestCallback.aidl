// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.base;

import org.chromium.base.ITestController;
import org.chromium.base.MainReturnCodeResult;
import org.chromium.base.process_launcher.FileDescriptorInfo;

/**
 * This interface is called by the child process to pass its controller to its parent.
 */
oneway interface ITestCallback {
  void childConnected(ITestController controller);
}
