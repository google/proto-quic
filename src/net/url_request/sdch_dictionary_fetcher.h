// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(rdsmith): This class needs to delegate URLRequest::Delegate methods
// to the net/ embedder for correct implementation of authentication.
// Specifically, this class needs the embedder to provide functionality
// corresponding to
// URLRequest::Delegate::{OnAuthRequired,OnCertificateRequested}.

#ifndef NET_URL_REQUEST_SDCH_DICTIONARY_FETCHER_H_
#define NET_URL_REQUEST_SDCH_DICTIONARY_FETCHER_H_

#include <memory>
#include <string>

#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "base/threading/non_thread_safe.h"
#include "net/base/net_export.h"
#include "net/base/sdch_manager.h"
#include "net/url_request/url_fetcher_delegate.h"
#include "net/url_request/url_request.h"
#include "url/gurl.h"

namespace net {

class NetLogWithSource;
class URLRequest;

// This class is used by embedder SDCH policy object to fetch
// dictionaries. It queues requests for dictionaries and dispatches
// them serially, implementing the URLRequest::Delegate interface to
// handle callbacks (but see above TODO). It tracks all requests, only
// attempting to fetch each dictionary once.
class NET_EXPORT SdchDictionaryFetcher : public URLRequest::Delegate,
                                         public base::NonThreadSafe {
 public:
  typedef base::Callback<void(const std::string& dictionary_text,
                              const GURL& dictionary_url,
                              const NetLogWithSource& net_log,
                              bool was_from_cache)>
      OnDictionaryFetchedCallback;

  // The consumer must guarantee that |*context| outlives this object.
  explicit SdchDictionaryFetcher(URLRequestContext* context);
  ~SdchDictionaryFetcher() override;

  // Request a new dictionary fetch.  The callback will be called
  // only if the dictionary is successfully fetched. Returns true if a
  // request for |dictionary_url| has been scheduled, and false otherwise.
  virtual bool Schedule(const GURL& dictionary_url,
                        const OnDictionaryFetchedCallback& callback);

  // Request a dictionary fetch from cache only.  The callback will be called
  // only if the dictionary is successfully fetched. Returns true if a request
  // for |dictionary_url| has been scheduled, and false otherwise.
  virtual bool ScheduleReload(const GURL& dictionary_url,
                              const OnDictionaryFetchedCallback& callback);

  // Cancel any in-progress requests.
  virtual void Cancel();

  // Implementation of URLRequest::Delegate methods.
  void OnReceivedRedirect(URLRequest* request,
                          const RedirectInfo& redirect_info,
                          bool* defer_redirect) override;
  void OnResponseStarted(URLRequest* request, int net_error) override;
  void OnReadCompleted(URLRequest* request, int bytes_read) override;

 private:
  enum State {
    STATE_NONE,
    STATE_SEND_REQUEST,
    STATE_RECEIVED_REDIRECT,
    STATE_SEND_REQUEST_PENDING,
    STATE_READ_BODY,
    STATE_READ_BODY_COMPLETE,
    STATE_REQUEST_COMPLETE,
  };

  class UniqueFetchQueue;

  // Schedule implementation. Returns true if a request for |dictionary_url| has
  // been added to the queue, and false otherwise.
  bool ScheduleInternal(const GURL& dictionary_url,
                        bool reload,
                        const OnDictionaryFetchedCallback& callback);

  // Null out the current request and push the state machine to the
  // next request, if any.
  void ResetRequest();

  // State machine implementation.
  int DoLoop(int rv);
  int DoSendRequest(int rv);
  int DoReceivedRedirect(int rv);
  int DoSendRequestPending(int rv);
  int DoReadBody(int rv);
  int DoReadBodyComplete(int rv);
  int DoCompleteRequest(int rv);

  State next_state_;
  bool in_loop_;

  // A queue of URLs that are being used to download dictionaries.
  std::unique_ptr<UniqueFetchQueue> fetch_queue_;

  // The request, buffer, and consumer supplied data used for getting
  // the current dictionary.  All are null when a fetch is not in progress.
  std::unique_ptr<URLRequest> current_request_;
  scoped_refptr<IOBuffer> buffer_;
  OnDictionaryFetchedCallback current_callback_;

  // The currently accumulating dictionary. Stored as a unique_ptr so all memory
  // it consumes can be easily freed, as it gets quite big, and
  // std::string::clear() may not free memory.
  std::unique_ptr<std::string> dictionary_;

  // Store the URLRequestContext associated with the owning SdchManager for
  // use while fetching.
  URLRequestContext* const context_;

  DISALLOW_COPY_AND_ASSIGN(SdchDictionaryFetcher);
};

}  // namespace net

#endif  // NET_URL_REQUEST_SDCH_DICTIONARY_FETCHER_H_
