// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


// The file runs a series of Media Source Entensions (MSE) operations on a
// video tag.  The test takes several URL parameters described in
//loadTestParams() function.

(function() {
  function getPerfTimestamp() {
    return performance.now();
  }

  var pageStartTime = getPerfTimestamp();
  var bodyLoadTime;
  var pageEndTime;

  function parseQueryParameters() {
    var params = {};
    var r = /([^&=]+)=?([^&]*)/g;

    function d(s) { return decodeURIComponent(s.replace(/\+/g, ' ')); }

    var match;
    while (match = r.exec(window.location.search.substring(1)))
      params[d(match[1])] = d(match[2]);

    return params;
  }

  var testParams;
  function loadTestParams() {
    var queryParameters = parseQueryParameters();
    testParams = {};
    testParams.testType = queryParameters["testType"] || "AV";
    testParams.useAppendStream = (queryParameters["useAppendStream"] == "true");
    testParams.doNotWaitForBodyOnLoad =
        (queryParameters["doNotWaitForBodyOnLoad"] == "true");
    testParams.startOffset = 0;
    testParams.appendSize = parseInt(queryParameters["appendSize"] || "65536");
    testParams.graphDuration =
        parseInt(queryParameters["graphDuration"] || "1000");
  }

  function plotTimestamps(timestamps, graphDuration, element) {
    if (!timestamps)
      return;
    var c = document.getElementById('c');
    var ctx = c.getContext('2d');

    var bars = [
      { label: 'Page Load Total',
        start: pageStartTime,
        end: pageEndTime,
        color: '#404040' },
      { label: 'body.onload Delay',
        start: pageStartTime,
        end: bodyLoadTime,
        color: '#808080' },
      { label: 'Test Total',
        start: timestamps.testStartTime,
        end: timestamps.testEndTime,
        color: '#00FF00' },
      { label: 'MediaSource opening',
        start: timestamps.mediaSourceOpenStartTime,
        end: timestamps.mediaSourceOpenEndTime,
        color: '#008800' }
    ];

    var maxAppendEndTime = 0;
    for (var i = 0; i < timestamps.appenders.length; ++i) {
      var appender = timestamps.appenders[i];
      bars.push({ label: 'XHR',
                  start: appender.xhrStartTime,
                  end: appender.xhrEndTime,
                  color: '#0088FF' });
      bars.push({ label: 'Append',
                  start: appender.appendStartTime,
                  end: appender.appendEndTime,
                  color: '#00FFFF' });
      if (appender.appendEndTime > maxAppendEndTime) {
        maxAppendEndTime = appender.appendEndTime;
      }
    }

    bars.push({
        label: 'Post Append Delay',
        start: maxAppendEndTime,
        end: timestamps.testEndTime,
        color: '#B0B0B0' });

    var minTimestamp = Number.MAX_VALUE;
    for (var i = 0; i < bars.length; ++i) {
      minTimestamp = Math.min(minTimestamp, bars[i].start);
    }

    var graphWidth = c.width - 100;
    function convertTimestampToX(t) {
      return graphWidth * (t - minTimestamp) / graphDuration;
    }
    var y = 0;
    var barThickness = 20;
    c.height = bars.length * barThickness;
    ctx.font = (0.75 * barThickness) + 'px arial';
    for (var i = 0; i < bars.length; ++i) {
      var bar = bars[i];
      var xStart = convertTimestampToX(bar.start);
      var xEnd = convertTimestampToX(bar.end);
      ctx.fillStyle = bar.color;
      ctx.fillRect(xStart, y, xEnd - xStart, barThickness);

      ctx.fillStyle = 'black';
      var text = bar.label + ' (' + (bar.end - bar.start).toFixed(3) + ' ms)';
      ctx.fillText(text, xEnd + 10, y + (0.75 * barThickness));
      y += barThickness;
    }
    reportTelemetryMediaMetrics(bars, element);
  }

  function displayResults(stats) {
    var statsDiv = document.getElementById('stats');

    if (!stats) {
      statsDiv.innerHTML = "Test failed";
      return;
    }

    var statsMarkup = "Test passed<br><table>";
    for (var i in stats) {
      statsMarkup += "<tr><td style=\"text-align:right\">" + i + ":</td><td>" +
                     stats[i].toFixed(3) + " ms</td>";
    }
    statsMarkup += "</table>";
    statsDiv.innerHTML = statsMarkup;
  }

  function reportTelemetryMediaMetrics(stats, element) {
    var metrics = {};
    for (var i = 0; i < stats.length; ++i) {
      var bar = stats[i];
      var label = bar.label.toLowerCase().replace(/\s+|\./g, '_');
      var value =  (bar.end - bar.start).toFixed(3);
      console.log("appending to telemetry " + label + " : "  + value);
      _AppendMetric(metrics, label, value);
    }
    window.__testMetrics = {
      "id": element.id,
      "metrics": metrics
    };
  }

  function _AppendMetric(metrics, metric, value) {
    if (!metrics[metric])
      metrics[metric] = [];
    metrics[metric].push(value);
  }

  function updateControls(testParams) {
    var testTypeElement = document.getElementById("testType");
    for (var i in testTypeElement.options) {
      var option = testTypeElement.options[i];
      if (option.value == testParams.testType) {
        testTypeElement.selectedIndex = option.index;
      }
    }

    document.getElementById("useAppendStream").checked =
        testParams.useAppendStream;
    document.getElementById("doNotWaitForBodyOnLoad").checked =
        testParams.doNotWaitForBodyOnLoad;
    document.getElementById("appendSize").value = testParams.appendSize;
    document.getElementById("graphDuration").value = testParams.graphDuration;
  }

  function BufferAppender(mimetype, url, id, startOffset, appendSize) {
    this.mimetype = mimetype;
    this.url = url;
    this.id = id;
    this.startOffset = startOffset;
    this.appendSize = appendSize;
    this.xhr = new XMLHttpRequest();
    this.sourceBuffer = null;
  }

  BufferAppender.prototype.start = function() {
    this.xhr.addEventListener('loadend', this.onLoadEnd.bind(this));
    this.xhr.open('GET', this.url);
    this.xhr.setRequestHeader('Range', 'bytes=' + this.startOffset + '-' +
                              (this.startOffset + this.appendSize - 1));
    this.xhr.responseType = 'arraybuffer';
    this.xhr.send();

    this.xhrStartTime = getPerfTimestamp();
  };

  BufferAppender.prototype.onLoadEnd = function() {
    this.xhrEndTime = getPerfTimestamp();
    this.attemptAppend();
  };

  BufferAppender.prototype.onSourceOpen = function(mediaSource) {
    if (this.sourceBuffer)
      return;
    this.sourceBuffer = mediaSource.addSourceBuffer(this.mimetype);
  };

  BufferAppender.prototype.attemptAppend = function() {
    if (!this.xhr.response || !this.sourceBuffer)
      return;

    this.appendStartTime = getPerfTimestamp();

    if (this.sourceBuffer.appendBuffer) {
      this.sourceBuffer.addEventListener('updateend',
                                         this.onUpdateEnd.bind(this));
      this.sourceBuffer.appendBuffer(this.xhr.response);
    } else {
      this.sourceBuffer.append(new Uint8Array(this.xhr.response));
      this.appendEndTime = getPerfTimestamp();
    }

    this.xhr = null;
  };

  BufferAppender.prototype.onUpdateEnd = function() {
    this.appendEndTime = getPerfTimestamp();
  };

  BufferAppender.prototype.onPlaybackStarted = function() {
    var now = getPerfTimestamp();
    this.playbackStartTime = now;
    if (this.sourceBuffer.updating) {
      // Still appending but playback has already started so just abort the XHR
      // and append.
      this.sourceBuffer.abort();
      this.xhr.abort();
    }
  };

  BufferAppender.prototype.getXHRLoadDuration = function() {
    return this.xhrEndTime - this.xhrStartTime;
  };

  BufferAppender.prototype.getAppendDuration = function() {
    return this.appendEndTime - this.appendStartTime;
  };

  function StreamAppender(mimetype, url, id, startOffset, appendSize) {
    this.mimetype = mimetype;
    this.url = url;
    this.id = id;
    this.startOffset = startOffset;
    this.appendSize = appendSize;
    this.xhr = new XMLHttpRequest();
    this.sourceBuffer = null;
    this.appendStarted = false;
  }

  StreamAppender.prototype.start = function() {
    this.xhr.addEventListener('readystatechange',
                              this.attemptAppend.bind(this));
    this.xhr.addEventListener('loadend', this.onLoadEnd.bind(this));
    this.xhr.open('GET', this.url);
    this.xhr.setRequestHeader('Range', 'bytes=' + this.startOffset + '-' +
                              (this.startOffset + this.appendSize - 1));
    this.xhr.responseType = 'stream';
    if (this.xhr.responseType != 'stream') {
      EndTest("XHR does not support 'stream' responses.");
    }
    this.xhr.send();

    this.xhrStartTime = getPerfTimestamp();
  };

  StreamAppender.prototype.onLoadEnd = function() {
    this.xhrEndTime = getPerfTimestamp();
    this.attemptAppend();
  };

  StreamAppender.prototype.onSourceOpen = function(mediaSource) {
    if (this.sourceBuffer)
      return;
    this.sourceBuffer = mediaSource.addSourceBuffer(this.mimetype);
  };

  StreamAppender.prototype.attemptAppend = function() {
    if (this.xhr.readyState < this.xhr.LOADING) {
      return;
    }

    if (!this.xhr.response || !this.sourceBuffer || this.appendStarted)
      return;

    this.appendStartTime = getPerfTimestamp();
    this.appendStarted = true;
    this.sourceBuffer.addEventListener('updateend',
                                       this.onUpdateEnd.bind(this));
    this.sourceBuffer.appendStream(this.xhr.response);
  };

  StreamAppender.prototype.onUpdateEnd = function() {
    this.appendEndTime = getPerfTimestamp();
  };

  StreamAppender.prototype.onPlaybackStarted = function() {
    var now = getPerfTimestamp();
    this.playbackStartTime = now;
    if (this.sourceBuffer.updating) {
      // Still appending but playback has already started so just abort the XHR
      // and append.
      this.sourceBuffer.abort();
      this.xhr.abort();
      if (!this.appendEndTime)
        this.appendEndTime = now;

      if (!this.xhrEndTime)
        this.xhrEndTime = now;
    }
  };

  StreamAppender.prototype.getXHRLoadDuration = function() {
    return this.xhrEndTime - this.xhrStartTime;
  };

  StreamAppender.prototype.getAppendDuration = function() {
    return this.appendEndTime - this.appendStartTime;
  };

  // runAppendTest() sets testDone to true once all appends finish.
  var testDone = false;
  function runAppendTest(mediaElement, appenders, doneCallback) {
    var testStartTime = getPerfTimestamp();
    var mediaSourceOpenStartTime;
    var mediaSourceOpenEndTime;

    for (var i = 0; i < appenders.length; ++i) {
      appenders[i].start();
    }

    function onSourceOpen(event) {
      var mediaSource = event.target;

      mediaSourceOpenEndTime = getPerfTimestamp();

      for (var i = 0; i < appenders.length; ++i) {
        appenders[i].onSourceOpen(mediaSource);
      }

      for (var i = 0; i < appenders.length; ++i) {
        appenders[i].attemptAppend(mediaSource);
      }

      mediaElement.play();
    }

    var mediaSource;
    if (window['MediaSource']) {
      mediaSource = new window.MediaSource();
      mediaSource.addEventListener('sourceopen', onSourceOpen);
    } else {
      mediaSource = new window.WebKitMediaSource();
      mediaSource.addEventListener('webkitsourceopen', onSourceOpen);
    }

    var listener;
    var timeout;
    function checkForCurrentTimeChange() {
      if (testDone)
        return;

      if (mediaElement.readyState < mediaElement.HAVE_METADATA ||
          mediaElement.currentTime <= 0) {
        listener = window.requestAnimationFrame(checkForCurrentTimeChange);
        return;
      }

      var testEndTime = getPerfTimestamp();
      for (var i = 0; i < appenders.length; ++i) {
        appenders[i].onPlaybackStarted(mediaSource);
      }

      testDone = true;
      window.clearInterval(listener);
      window.clearTimeout(timeout);

      var stats = {};
      stats.total = testEndTime - testStartTime;
      stats.sourceOpen = mediaSourceOpenEndTime - mediaSourceOpenStartTime;
      stats.maxXHRLoadDuration = appenders[0].getXHRLoadDuration();
      stats.maxAppendDuration = appenders[0].getAppendDuration();

      var timestamps = {};
      timestamps.testStartTime = testStartTime;
      timestamps.testEndTime = testEndTime;
      timestamps.mediaSourceOpenStartTime = mediaSourceOpenStartTime;
      timestamps.mediaSourceOpenEndTime = mediaSourceOpenEndTime;
      timestamps.appenders = [];

      for (var i = 1; i < appenders.length; ++i) {
        var appender = appenders[i];
        var xhrLoadDuration = appender.getXHRLoadDuration();
        var appendDuration = appender.getAppendDuration();

        if (xhrLoadDuration > stats.maxXHRLoadDuration)
          stats.maxXHRLoadDuration = xhrLoadDuration;

        if (appendDuration > stats.maxAppendDuration)
          stats.maxAppendDuration = appendDuration;
      }

      for (var i = 0; i < appenders.length; ++i) {
        var appender = appenders[i];
        var appenderTimestamps = {};
        appenderTimestamps.xhrStartTime = appender.xhrStartTime;
        appenderTimestamps.xhrEndTime = appender.xhrEndTime;
        appenderTimestamps.appendStartTime = appender.appendStartTime;
        appenderTimestamps.appendEndTime = appender.appendEndTime;
        appenderTimestamps.playbackStartTime = appender.playbackStartTime;
        timestamps.appenders.push(appenderTimestamps);
      }

      mediaElement.pause();

      pageEndTime = getPerfTimestamp();
      doneCallback(stats, timestamps);
    };

    listener = window.requestAnimationFrame(checkForCurrentTimeChange);

    timeout = setTimeout(function() {
      if (testDone)
        return;

      testDone = true;
      window.cancelAnimationFrame(listener);

      mediaElement.pause();
      doneCallback(null);
      EndTest("Test timed out.");
    }, 10000);

    mediaSourceOpenStartTime = getPerfTimestamp();
    mediaElement.src = URL.createObjectURL(mediaSource);
  };

  function onBodyLoad() {
    bodyLoadTime = getPerfTimestamp();

    if (!testParams.doNotWaitForBodyOnLoad) {
      startTest();
    }
  }

  function startTest() {
    updateControls(testParams);

    var appenders = [];

    if (testParams.useAppendStream && !window.MediaSource)
      EndTest("Can't use appendStream() because the unprefixed MediaSource " +
              "object is not present.");

    var Appender = testParams.useAppendStream ? StreamAppender : BufferAppender;

    if (testParams.testType.indexOf("A") != -1) {
      appenders.push(
          new Appender("audio/mp4; codecs=\"mp4a.40.2\"",
                       "audio.mp4",
                       "a",
                       testParams.startOffset,
                       testParams.appendSize));
    }

    if (testParams.testType.indexOf("V") != -1) {
      appenders.push(
          new Appender("video/mp4; codecs=\"avc1.640028\"",
                       "video.mp4",
                       "v",
                       testParams.startOffset,
                       testParams.appendSize));
    }

    var video = document.getElementById("v");
    video.addEventListener("error", function(e) {
      console.log("video error!");
      EndTest("Video error: " + video.error);
    });

    video.id = getTestID();
    runAppendTest(video, appenders, function(stats, timestamps) {
      displayResults(stats);
      plotTimestamps(timestamps, testParams.graphDuration, video);
      EndTest("Call back call done.");
    });
  }

  function EndTest(msg) {
    console.log("Ending test: " + msg);
    window.__testDone = true;
  }

  function getTestID() {
    var id = testParams.testType;
    if (testParams.useAppendStream)
      id += "_stream"
    else
      id += "_buffer"
    if (testParams.doNotWaitForBodyOnLoad)
      id += "_pre_load"
    else
      id += "_post_load"
    return id;
  }

  function setupTest() {
    loadTestParams();
    document.body.onload = onBodyLoad;

    if (testParams.doNotWaitForBodyOnLoad) {
      startTest();
    }
  }

  window["setupTest"] = setupTest;
  window.__testDone = false;
  window.__testMetrics = {};
})();
