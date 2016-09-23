// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

(function() {
window.testRunner = {};
window.testRunner.isDone = false;

testRunner.waitUntilDone = function() {};
testRunner.dumpAsText = function() {};
testRunner.notifyDone = function() {
  this.isDone = true;
};

window.GCController = {};

GCController.collect = function() {
  gc();
};
GCController.collectAll = function() {
  for (var i = 0; i < 7; ++i)
    gc();
};
})();
