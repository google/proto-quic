// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

function get_query(uri, key) {
  if (uri.includes('?')) {
    let query_str = uri.split('?')[1];
    let queries = query_str.split('&');
    for (let query of queries) {
      let ss = query.split('=');
      if (ss.length == 2 && ss[0] == key)
        return ss[1];
    }
  }
  return undefined;
}

function open_by_selection(selectionText) {
  if (selectionText)
    fetch('http://127.0.0.1:8989/file?f=' + selectionText + '&l=1');
}

function open_by_link(pageUrl, info, tabId) {
  if (pageUrl.startsWith('https://cs.chromium.org/')) {
    if (info.linkUrl.startsWith('https://cs.chromium.org/chromium/src/')) {
      let filepath =
          info.linkUrl.replace('https://cs.chromium.org/chromium/src/', '')
              .replace(/\?.*/, '');
      let line = get_query(info.linkUrl, 'l');
      line = line != undefined ? line : '1';
      fetch('http://127.0.0.1:8989/file?f=' + filepath + '&l=' + line);
    }
  } else if (pageUrl.startsWith('https://codereview.chromium.org/')) {
    if (info.linkUrl.match('https://codereview.chromium.org/.*/patch/') !=
        null) {
      chrome.tabs.sendMessage(tabId, 'getFile', (res) => {
        if (res.file)
          fetch('http://127.0.0.1:8989/file?f=' + res.file + '&l=1');
      });
    } else if (
        info.linkUrl.match(
            /https:\/\/codereview.chromium.org\/\d*\/diff\/\d*\//) != null) {
      let filepath = info.linkUrl.replace(
          /https:\/\/codereview.chromium.org\/\d*\/diff\/\d*\//, '');
      fetch('http://127.0.0.1:8989/file?f=' + filepath + '&l=1');
    }
  }
}

function cs_open_by_current_line(tabId, url) {
  chrome.tabs.sendMessage(tabId, 'getLine', (res) => {
    let line = res.line;

    let filepath = url.replace('https://cs.chromium.org/chromium/src/', '')
                       .replace(/\?.*/, '');

    fetch('http://127.0.0.1:8989/file?f=' + filepath + '&l=' + line);
  });
}

function cr_open_all_in_patchset(tabId) {
  chrome.tabs.sendMessage(tabId, 'getFiles', (res) => {
    fetch('http://127.0.0.1:8989/files?f=' + res.files.join(',,'));
  });
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
  if (info.menuItemId == 'ome-selection') {
    open_by_selection(info.selectionText);
  } else if (info.menuItemId == 'ome-link') {
    open_by_link(tab.url, info, tab.id);
  } else if (info.menuItemId == 'ome') {
    if (tab.url.startsWith('https://cs.chromium.org/chromium/src/')) {
      cs_open_by_current_line(tab.id, tab.url);
    } else if (tab.url.startsWith('https://codereview.chromium.org/')) {
      cr_open_all_in_patchset(tab.id);
    }
  }
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    'title': 'Open My Editor',
    'id': 'ome',
    'contexts': ['page'],
    'documentUrlPatterns': [
      'https://cs.chromium.org/chromium/src/*',
      'https://codereview.chromium.org/*'
    ]
  });
  chrome.contextMenus.create({
    'title': 'Open My Editor by Link',
    'id': 'ome-link',
    'contexts': ['link'],
    'documentUrlPatterns':
        ['https://cs.chromium.org/*', 'https://codereview.chromium.org/*']
  });
  chrome.contextMenus.create({
    'title': 'Open My Editor for "%s"',
    'id': 'ome-selection',
    'contexts': ['selection'],
    'documentUrlPatterns': [
      // TODO(chaopeng) Should be only except CS and CR, But I dont know how to.
      // So only list the sites here.
      'https://build.chromium.org/*', 'https://chromium.org/*'
    ]
  });
});
