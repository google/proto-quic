// Copyright 2015 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

/**
 * @fileoverview Main module for the Chromium Code Coverage extension. This
 *               extension adds incremental and absolute code coverage stats
 *               to the deprecated Rietveld UI. Stats are added inline  with
 *               file names as percentage of lines covered.
 */

 var coverage = coverage || {};

/**
 * Contains all required configuration information.
 *
 * @type {Object}
 * @const
 */
coverage.CONFIG = {};

/**
 * URLs necessary for each project. These are necessary because the Rietveld
 * sites are used by other projects as well, and is is only possible to find
 * coverage stats for the projects registered here.
 *
 * @type {Object}
 * @const
 */
coverage.CONFIG.COVERAGE_REPORT_URLS = {
  'Android': {
    prefix: 'https://build.chromium.org/p/tryserver.chromium.linux/builders/' +
            'android_coverage/builds/',
    suffix: '/steps/Incremental%20coverage%20report/logs/json.output',
    botUrl: 'http://build.chromium.org/p/tryserver.chromium.linux/builders/' +
            'android_coverage'
  },
  'iOS': {
    prefix: 'https://uberchromegw.corp.google.com/i/internal.bling.tryserver/' +
            'builders/coverage/builds/',
    suffix: '/steps/coverage/logs/json.output',
    botUrl: 'https://uberchromegw.corp.google.com/i/internal.bling.tryserver/' +
            'builders/coverage'
  }
};

/**
 * URLs where Rietveld apps are served. URLs should be escaped properly so that
 * they are ready to be used in regular expressions.
 *
 * @type {Array.<string>}
 */
coverage.CONFIG.CODE_REVIEW_URLS = [
  'https:\\/\\/codereview\\.chromium\\.org',
  'https:\\/\\/chromereviews\\.googleplex\\.com'
];

/**
  * String representing absolute coverage.
  *
  * @type {string}
  * @const
*/
coverage.ABSOLUTE_COVERAGE = 'absolute';

/**
  * String representing incremental coverage.
  *
  * @type {string}
  * @const
*/
coverage.INCREMENTAL_COVERAGE = 'incremental';

/**
 * String representing patch incremental coverage.
 *
 * @type {string}
 * @const
 */
coverage.PATCH_COVERAGE = 'patch';

/**
 * Fetches detailed coverage stats for a given patch set and injects them into
 * the code review page.
 *
 * @param  {Element} patchElement Div containing a single patch set.
 * @param  {string} botUrl Location of the detailed coverage bot results.
 * @param  {string} projectName The name of project to which code was submitted.
 */
coverage.injectCoverageStats = function(patchElement, botUrl, projectName) {
  var buildNumber = botUrl.split('/').pop();
  var patch = new coverage.PatchSet(projectName, buildNumber);
  patch.getCoverageData(function(patchStats) {
    coverage.updateUi(patchStats, patchElement, patch.getCoverageReportUrl());
  });
};

/**
 * Adds coverage stats to the table containing files changed for a given patch.
 *
 * @param  {Object} patchStats Object containing stats for a given patch set.
 * @param  {Element} patchElement Div containing a patch single set.
 * @param  {string} reportUrl Location of the detailed coverage stats for this
 *                  patch.
 */
coverage.updateUi = function(patchStats, patchElement, reportUrl) {
  // Add absolute and incremental coverage column headers.
  var patchSetTableBody = patchElement.getElementsByTagName('tbody')[0];
  var headerRow = patchSetTableBody.firstElementChild;
  coverage.appendElementBeforeChild(headerRow, 'th', '&Delta;Cov.', 1);
  coverage.appendElementBeforeChild(headerRow, 'th', '|Cov.|', 1);

  // Add absolute and incremental coverage stats for each file.
  var fileRows = patchElement.querySelectorAll('[name=patch]');
  for (var i = 0; i < fileRows.length; i++) {
    var sourceFileRow = fileRows[i];
    var fileName = sourceFileRow.children[2].textContent.trim();

    var incrementalPercent = null;
    var absolutePercent = null;
    if (patchStats[fileName]) {
      incrementalPercent = patchStats[fileName][coverage.INCREMENTAL_COVERAGE];
      absolutePercent = patchStats[fileName][coverage.ABSOLUTE_COVERAGE];
    }

    coverage.appendElementBeforeChild(
        sourceFileRow, 'td', coverage.formatPercent(incrementalPercent), 2);

    coverage.appendElementBeforeChild(
        sourceFileRow, 'td', coverage.formatPercent(absolutePercent), 2);
  }
  // Add the overall coverage stats for the patch.
  coverage.addPatchSummaryStats(
      patchElement, patchStats[coverage.PATCH_COVERAGE], reportUrl);
};

/**
 * Formats percent for presentation on the page.
 *
 * @param  {number} coveragePercent
 * @return {string} Formatted string ready to be added to the the DOM.
 */
coverage.formatPercent = function(coveragePercent) {
  if (!coveragePercent) {
    return '-';
  } else {
    return coveragePercent + '%';
  }
};

/**
 * Adds summary line to a patch element: "Cov. for this patch: 45%. Details".
 *
 * @param {Element} patchElement Div containing a patch single patch set.
 * @param {number} coveragePercent Incremental coverage for entire patch.
 * @param {string} coverageReportUrl Location of detailed coverage report.
 */
coverage.addPatchSummaryStats = function(
    patchElement, coveragePercent, coverageReportUrl) {
  var summaryElement = document.createElement('div');
  var patchSummaryHtml = '&Delta;Cov. for this patch: ' +
                         coverage.formatPercent(coveragePercent) + '.&nbsp;';
  var detailsHtml = '<a href="' + coverageReportUrl + '">Details</a>';
  summaryElement.innerHTML = patchSummaryHtml + ' ' + detailsHtml;

  // Insert the summary line immediately after the table containing the changed
  // files for the patch.
  var tableElement = patchElement.getElementsByTagName('table')[0];
  tableElement.parentNode.insertBefore(
      summaryElement, tableElement.nextSibling);
};

/**
 * Creates and prepends an element before another.
 *
 * @param  {Element} parentElement The parent of the element to prepend a new
 *                   element to.
 * @param  {string} elementType The tag name for the new element.
 * @param  {string} innerHtml The value to set as the new element's innerHTML
 * @param  {number} childNumber The index of the child to prepend to.
 */
coverage.appendElementBeforeChild = function(
    parentElement, elementType, innerHtml, childNumber) {
  var newElement = document.createElement(elementType);
  newElement.innerHTML = innerHtml;
  parentElement.insertBefore(newElement, parentElement.children[childNumber]);
};

/**
 * Checks if the given URL has been registered or not.
 *
 * @param  {string} botUrl The URL to be verified.
 * @return {boolean} Whether or not the provided URL was valid.
 */
coverage.isValidBotUrl = function(botUrl) {
  if (!botUrl) {
    return false;
  }
  for (var project in coverage.CONFIG.COVERAGE_REPORT_URLS) {
    var candidateUrl = coverage.CONFIG.COVERAGE_REPORT_URLS[project]['botUrl'];
    if (botUrl.indexOf(candidateUrl) > - 1) {
      return true;
    }
  }
  return false;
};

/**
 * Returns the project name for the given bot URL. This function expects the bot
 * URL to be valid.
 *
 * @param  {botUrl} botUrl
 * @return {string} The project name for the given bot URL.
 * @throws {Error} If an invalid bot URL is supplied.
 */
coverage.getProjectNameFromBotUrl = function(botUrl) {
  if (!botUrl) {
    throw Error(botUrl + ' is an invalid bot url.');
  }
  for (var project in coverage.CONFIG.COVERAGE_REPORT_URLS) {
    var candidateUrl = coverage.CONFIG.COVERAGE_REPORT_URLS[project]['botUrl'];
    if (botUrl.indexOf(candidateUrl) > - 1) {
      return project;
    }
  }
  throw Error(botUrl + ' is not registered.');
};


/**
 * Finds the coverage bot URL.
 *
 * @param  {Element} patchElement Div to search for bot URL.
 * @return {string} Returns the URL to the bot details page.
 */
coverage.getValidBotUrl = function(patchElement) {
  var bots = patchElement.getElementsByClassName('build-result');
  for (var i = 0; i < bots.length; i++) {
    if (bots[i].getAttribute('status') === 'success' &&
        coverage.isValidBotUrl(bots[i].href)) {
      return bots[i].href;
    }
  }
  return null;
};

/**
 * Checks to see if the URL points to a CL review and not another page on the
 * code review site (i.e. settings).
 *
 * @param  {string} url The URL to verify.
 * @return {boolean} Whether or not the URL points to a CL review.
 */
coverage.isValidReviewUrl = function(url) {
  baseUrls = coverage.CONFIG.CODE_REVIEW_URLS.join('|');
  // Matches baseurl.com/numeric-digits and baseurl.com/numeric-digits/anything
  var re = new RegExp('(' + baseUrls + ')/[\\d]+(\\/|$)', 'i');
  return !!url.match(re);
};

/**
 * Verifies that the user is using the deprecated UI.
 *
 * @return {boolean} Whether or not the deprecated UI is being used.
 */
coverage.isDeprecatedUi = function() {
  // The tag is present in the new UI only.
  return document.getElementsByTagName('cr-app').length == 0;
};

/**
 * Returns the newest patch set element.
 *
 * @return {Element} The main div for the last patch set.
 */
coverage.getLastPatchElement = function() {
  var patchElement = document.querySelectorAll('div[id^="ps-"');
  return patchElement[patchElement.length - 1];
};

/**
 * Model that describes a patch set.
 *
 * @param {string} projectName The name of the project.
 * @param {string} buildNumber The build number for the bot run corresponding to
 *                 this patch set.
 * @constructor
 */
coverage.PatchSet = function(projectName, buildNumber) {
  /**
   * Location of the detailed coverage JSON report.
   * @type {string}
   * @private
   */
  this.coverageReportUrl_ = this.getCoverageReportUrl(projectName, buildNumber);
};

/**
 * Returns the coverage report URL.
 *
 * @param {string} projectName The name of the project.
 * @param {string} buildNumber The build number for the bot run corresponding
 *                 to this patch set.
 * @return {string} The URL to the detailed coverage report.
 */
coverage.PatchSet.prototype.getCoverageReportUrl = function(
    projectName, buildNumber) {
  if (!this.coverageReportUrl_) {
    var reportUrl = coverage.CONFIG.COVERAGE_REPORT_URLS[projectName];
    this.coverageReportUrl_ = reportUrl['prefix'] + buildNumber +
                              reportUrl['suffix'];
  }
  return this.coverageReportUrl_;
};

/**
 * Returns the detailed coverage report. Caller must handle what happens
 * when the report is received. No side effects if report isn't sent.
 *
 * @param  {function} success The callback to be invoked when the report is
 *                    received. Invoked with an object mapping file names to
 *                    coverage stats as the only argument.
 */
coverage.PatchSet.prototype.getCoverageData = function(success) {
  var client = new coverage.HttpClient();
  client.get(this.coverageReportUrl_, (function(data) {
    var resultDict = JSON.parse(data);
    var coveragePercentages = this.getCoveragePercentForFiles(resultDict);
    success(coveragePercentages);
  }).bind(this));
};

/**
 * Extracts the coverage percent for each file from the coverage report.
 *
 * @param  {Object} reportDict The detailed coverage report.
 * @return {Object} An object containing the coverage percent for each file and
 *                  the patch coverage percent.
 */
coverage.PatchSet.prototype.getCoveragePercentForFiles = function(reportDict) {
  var fileDict = reportDict['files'];
  var coveragePercentages = {};

  for (var fileName in fileDict) {
    if (fileDict.hasOwnProperty(fileName)) {
      coveragePercentages[fileName] = {};
      var coverageDict = fileDict[fileName];

      coveragePercentages[fileName][coverage.ABSOLUTE_COVERAGE] =
          this.getCoveragePercent(coverageDict, coverage.ABSOLUTE_COVERAGE);

      coveragePercentages[fileName][coverage.INCREMENTAL_COVERAGE] =
          this.getCoveragePercent(coverageDict, coverage.INCREMENTAL_COVERAGE);
    }
  }
  coveragePercentages[coverage.PATCH_COVERAGE] =
      this.getCoveragePercent(reportDict[coverage.PATCH_COVERAGE],
                              coverage.INCREMENTAL_COVERAGE);
  return coveragePercentages;
};

/**
 * Returns the coverage percent given the number of total and covered lines.
 *
 * @param  {Object} coverageDict Object containing absolute and incremental
 *                  number of lines covered.
 * @param  {string} coverageType Either 'incremental' or 'absolute'.
 * @return {number} The coverage percent.
 */
coverage.PatchSet.prototype.getCoveragePercent = function(
    coverageDict, coverageType) {
  if (!coverageDict ||
      (coverageType !== coverage.INCREMENTAL_COVERAGE &&
       coverageType !== coverage.ABSOLUTE_COVERAGE) ||
      parseFloat(total) === 0) {
    return null;
  }
  var covered = coverageDict[coverageType]['covered'];
  var total = coverageDict[coverageType]['total'];
  return Math.round(
      (parseFloat(covered) / parseFloat(total)) * 100);
};

/**
 * Model describing a simple HTTP client. Only supports GET requests.
 */
coverage.HttpClient = function() {
};

/**
 * HTTP GET that only handles successful requests.
 *
 * @param  {string} url The URL to make a GET request to.
 * @param  {function} success The callback invoked when the request is finished
 *                    successfully. Callback is invoked with response text as
 *                    the only argument.
 */
coverage.HttpClient.prototype.get = function(url, success) {
  // TODO(estevenson): Handle failure when user isn't authenticated.
  var http = new XMLHttpRequest();
  http.onreadystatechange = function() {
    if (http.readyState === 4 && http.status === 200) {
      success(http.responseText);
    }
  };

  http.open('GET', url + '/text', true);
  http.send(null);
};

// Verifies that page might contain a patch set with a valid coverage bot.
if (coverage.isDeprecatedUi() &&
    coverage.isValidReviewUrl(window.location.href)) {
  var patchElement = coverage.getLastPatchElement();
  var botUrl = coverage.getValidBotUrl(patchElement);
  if (botUrl) {
    var projectName = coverage.getProjectNameFromBotUrl(botUrl);
    coverage.injectCoverageStats(patchElement, botUrl, projectName);
  }
}
