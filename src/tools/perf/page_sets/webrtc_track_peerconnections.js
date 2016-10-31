// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file overwrites the RTCPeerConnection constructor with a new constructor
// which tracks all created connections. It does this by periodically gathering
// statistics on all connections, using the WebRTC statistics API. All reports
// are gathered into window.peerConnectionReports, which contains one list per
// connection. In each list there is a number of report batches, which in turn
// contains metric names mapped to values.

window.peerConnectionReports = [];

RTCPeerConnection = webkitRTCPeerConnection = (function() {
  function getReportsAsDicts(getStatsResult) {
    var result = [];
    getStatsResult.forEach(function(report) {
      var values = {};
      report.names().forEach(function(name) {
        values[name] = report.stat(name);
      });
      result.push(values);
    });
    return result;
  }

  function gatherStatsFromOneConnection(peerConnection) {
    var connectionId = window.peerConnectionReports.length;
    window.peerConnectionReports.push([]);
    var pollIntervalMs = 1000;

    setInterval(function() {
      peerConnection.getStats(function(response) {
        var reports = getReportsAsDicts(response.result());
        window.peerConnectionReports[connectionId].push(reports);
      });
    }, pollIntervalMs);
  }

  var originalConstructor = RTCPeerConnection;
  return function() {
    // Bind the incoming arguments to the original constructor.
    var args = [null].concat(Array.prototype.slice.call(arguments));
    var factoryFunction = originalConstructor.bind.apply(
      originalConstructor, args);

    // Create the object and track it.
    var peerConnection = new factoryFunction();
    gatherStatsFromOneConnection(peerConnection);
    return peerConnection;
  }
})();
