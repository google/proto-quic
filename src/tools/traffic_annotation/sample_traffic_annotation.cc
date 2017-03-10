// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/traffic_annotation/network_traffic_annotation.h"

// This file includes a sample and a template for text-coded traffic_annotation.
// For more description on each field, please refer to:
// tools/traffic_annotation/traffic_annotation.proto
// and
// out/Debug/gen/components/policy/proto/chrome_settings.proto
// For more information on policies, please refer to:
// http://dev.chromium.org/administrators/policy-list-3

void network_traffic_annotation_sample() {
  net::NetworkTrafficAnnotationTag traffic_annotation =
      net::DefineNetworkTrafficAnnotation("spellcheck_lookup", R"(
        semantics {
          sender: "Online Spellcheck"
          description:
            "Google Chrome can provide smarter spell-checking by sending "
            "text you type into the browser to Google's servers, allowing "
            "you to use the same spell-checking technology used by Google "
            "products, such as Docs. If the feature is enabled, Chrome will "
            "send the entire contents of text fields as you type in them to "
            "Google along with the browser’s default language. Google "
            "returns a list of suggested spellings, which will be displayed "
            "in the context menu."
          trigger: "User types text into a text field or asks to correct a "
                   "misspelled word."
          data: "Text a user has typed into a text field. No user identifier "
                "is sent along with the text."
          destination: GOOGLE_OWNED_SERVICE
        }
        policy {
          cookies_allowed: false
          setting:
            "You can enable or disable this feature via 'Use a web service to "
            "help resolve spelling errors.' in Chrome's settings under "
            "Advanced. The feature is disabled by default."
          chrome_policy {
            SpellCheckServiceEnabled {
                policy_options {mode: MANDATORY}
                SpellCheckServiceEnabled: false
            }
          }
        })");
}

void network_traffic_annotation_template() {
  net::NetworkTrafficAnnotationTag traffic_annotation =
      net::DefineNetworkTrafficAnnotation("...", R"(
        semantics {
          sender: "..."
          description: "..."
          trigger: "..."
          data: "..."
          destination: WEBSITE/GOOGLE_OWNED_SERVICE/OTHER
        }
        policy {
          cookies_allowed: false/true
          cookies_store: "..."
          setting: "..."
          chrome_policy {
            [POLICY_NAME] {
                policy_options {mode: MANDATORY/RECOMMENDED/UNSET}
                [POLICY_NAME]: ...
            }
          }
          policy_exception_justification = "..."
        })");
}