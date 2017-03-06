// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// For codereview.chromium.org

let clicked_element = null;

document.addEventListener('mousedown', (event) => {
  // right click
  if (event.button == 2)
    clicked_element = event.target;
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request == 'getFiles') {
    let element = clicked_element;
    while (element != null && element.tagName != 'TABLE')
      element = element.parentElement;

    let trs = element.getElementsByTagName('TR');
    if (trs.length == 0)
      alert('Please toggle one patchset.');

    let files = [];
    for (let i = 1; i < trs.length; ++i) {
      let tr = trs[i];
      if (tr.getAttribute('name') != 'patch')
        continue;
      // Skip deleted file.
      if (tr.children[1].firstChild.data == 'D')
        continue;

      files.push(tr.children[2].children[0].text.replace(/\s*/g, ''));
    }

    sendResponse({files: files});
  } else if (request == 'getFile' && clicked_element.tagName == 'A') {
    sendResponse({file: clicked_element.text});
  }
});