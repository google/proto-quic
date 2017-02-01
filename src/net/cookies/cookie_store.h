// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Brought to you by number 42.

#ifndef NET_COOKIES_COOKIE_STORE_H_
#define NET_COOKIES_COOKIE_STORE_H_

#include <memory>
#include <string>
#include <vector>

#include "base/callback_forward.h"
#include "base/callback_list.h"
#include "base/time/time.h"
#include "net/base/net_export.h"
#include "net/cookies/canonical_cookie.h"
#include "net/cookies/cookie_options.h"

class GURL;

namespace net {

// An interface for storing and retrieving cookies. Implementations are not
// thread safe, as with most other net classes. All methods must be invoked on
// the network thread, and all callbacks will be calle there.
//
// All async functions may either invoke the callback asynchronously, or they
// may be invoked immediately (prior to return of the asynchronous function).
// Destroying the CookieStore will cancel pending async callbacks.
class NET_EXPORT CookieStore {
 public:
  // The publicly relevant reasons a cookie might be changed.
  enum class ChangeCause {
    // The cookie was inserted.
    INSERTED,
    // The cookie was changed directly by a consumer's action.
    EXPLICIT,
    // The following four values have the same meaning as EXPLICIT, but are
    // being used to track down where a bug is coming from.
    // TODO(nharper): Remove the following four values once the one of interest
    // has been found.
    EXPLICIT_DELETE_BETWEEN,
    EXPLICIT_DELETE_PREDICATE,
    EXPLICIT_DELETE_SINGLE,
    EXPLICIT_DELETE_CANONICAL,
    // The cookie was deleted, but no more details are known.
    UNKNOWN_DELETION,
    // The cookie was automatically removed due to an insert operation that
    // overwrote it.
    OVERWRITE,
    // The cookie was automatically removed as it expired.
    EXPIRED,
    // The cookie was automatically evicted during garbage collection.
    EVICTED,
    // The cookie was overwritten with an already-expired expiration date.
    EXPIRED_OVERWRITE
  };

  // Returns whether |cause| is one that could be a reason for deleting a
  // cookie. This function assumes that ChangeCause::EXPLICIT is a reason for
  // deletion.
  static bool ChangeCauseIsDeletion(ChangeCause cause);

  // Callback definitions.
  typedef base::Callback<void(const CookieList& cookies)> GetCookieListCallback;
  typedef base::Callback<void(const std::string& cookie)> GetCookiesCallback;
  typedef base::Callback<void(bool success)> SetCookiesCallback;
  typedef base::Callback<void(int num_deleted)> DeleteCallback;
  typedef base::Callback<void(const CanonicalCookie& cookie, ChangeCause cause)>
      CookieChangedCallback;
  typedef base::CallbackList<void(const CanonicalCookie& cookie,
                                  ChangeCause cause)>
      CookieChangedCallbackList;
  typedef CookieChangedCallbackList::Subscription CookieChangedSubscription;
  typedef base::Callback<bool(const CanonicalCookie& cookie)> CookiePredicate;

  virtual ~CookieStore();

  // Returns the cookie line (e.g. "cookie1=value1; cookie2=value2") represented
  // by |cookies|. The string is built in the same order as the given list.
  //
  // TODO(mkwst): We really should standardize on either
  // 'std::vector<CanonicalCookie>' or 'std::vector<CanonicalCookie*>'.
  static std::string BuildCookieLine(
      const std::vector<CanonicalCookie>& cookies);
  static std::string BuildCookieLine(
      const std::vector<CanonicalCookie*>& cookies);

  // Sets the cookies specified by |cookie_list| returned from |url|
  // with options |options| in effect.  Expects a cookie line, like
  // "a=1; domain=b.com".
  //
  // Fails either if the cookie is invalid or if this is a non-HTTPONLY cookie
  // and it would overwrite an existing HTTPONLY cookie.
  // Returns true if the cookie is successfully set.
  virtual void SetCookieWithOptionsAsync(
      const GURL& url,
      const std::string& cookie_line,
      const CookieOptions& options,
      const SetCookiesCallback& callback) = 0;

  // Sets a cookie given explicit user-provided cookie attributes. The cookie
  // name, value, domain, etc. are each provided as separate strings. This
  // function expects each attribute to be well-formed. It will check for
  // disallowed characters (e.g. the ';' character is disallowed within the
  // cookie value attribute) and will return false without setting the cookie
  // if such characters are found.
  //
  // If |creation_time| is null, it will be set to the time the cookie is set.
  // If |last_access_time| is null, it be set to |creation_time|.
  //
  // If unable to set a cookie, will  invoke |callback| with false.
  virtual void SetCookieWithDetailsAsync(
      const GURL& url,
      const std::string& name,
      const std::string& value,
      const std::string& domain,
      const std::string& path,
      base::Time creation_time,
      base::Time expiration_time,
      base::Time last_access_time,
      bool secure,
      bool http_only,
      CookieSameSite same_site,
      CookiePriority priority,
      const SetCookiesCallback& callback) = 0;

  // TODO(???): what if the total size of all the cookies >4k, can we have a
  // header that big or do we need multiple Cookie: headers?
  // Note: Some sites, such as Facebook, occasionally use Cookie headers >4k.
  //
  // Simple interface, gets a cookie string "a=b; c=d" for the given URL.
  // Gets all cookies that apply to |url| given |options|. Use options to
  // access httponly cookies.
  //
  // The returned cookies are ordered by longest path, then earliest
  // creation date.
  //
  // TODO(mkwst): This method is deprecated; callsites should be updated to
  // use 'GetCookieListWithOptionsAsync'.
  virtual void GetCookiesWithOptionsAsync(
      const GURL& url,
      const CookieOptions& options,
      const GetCookiesCallback& callback) = 0;

  // Obtains a CookieList for the given |url| and |options|. The returned
  // cookies are passed into |callback|, ordered by longest path, then earliest
  // creation date.
  virtual void GetCookieListWithOptionsAsync(
      const GURL& url,
      const CookieOptions& options,
      const GetCookieListCallback& callback) = 0;

  // Returns all cookies associated with |url|, including http-only, and
  // same-site cookies. The returned cookies are ordered by longest path, then
  // by earliest creation date, and are not marked as having been accessed.
  //
  // TODO(mkwst): This method is deprecated, and should be removed, either by
  // updating callsites to use 'GetCookieListWithOptionsAsync' with an explicit
  // CookieOptions, or by changing CookieOptions' defaults.
  void GetAllCookiesForURLAsync(const GURL& url,
                                const GetCookieListCallback& callback);

  // Returns all the cookies, for use in management UI, etc. This does not mark
  // the cookies as having been accessed. The returned cookies are ordered by
  // longest path, then by earliest creation date.
  virtual void GetAllCookiesAsync(const GetCookieListCallback& callback) = 0;

  // Deletes all cookies that might apply to |url| that have |cookie_name|.
  virtual void DeleteCookieAsync(const GURL& url,
                                 const std::string& cookie_name,
                                 const base::Closure& callback) = 0;

  // Deletes one specific cookie. |cookie| must have been returned by a previous
  // query on this CookieStore. Invokes |callback| with 1 if a cookie was
  // deleted, 0 otherwise.
  virtual void DeleteCanonicalCookieAsync(const CanonicalCookie& cookie,
                                          const DeleteCallback& callback) = 0;

  // Deletes all of the cookies that have a creation_date greater than or equal
  // to |delete_begin| and less than |delete_end|
  // Calls |callback| with the number of cookies deleted.
  virtual void DeleteAllCreatedBetweenAsync(const base::Time& delete_begin,
                                            const base::Time& delete_end,
                                            const DeleteCallback& callback) = 0;

  // Deletes all of the cookies that match the given predicate and that have a
  // creation_date greater than or equal to |delete_begin| and smaller than
  // |delete_end|. This includes all http_only and secure cookies. Avoid
  // deleting cookies that could leave websites with a partial set of visible
  // cookies.
  // Calls |callback| with the number of cookies deleted.
  virtual void DeleteAllCreatedBetweenWithPredicateAsync(
      const base::Time& delete_begin,
      const base::Time& delete_end,
      const CookiePredicate& predicate,
      const DeleteCallback& callback) = 0;

  virtual void DeleteSessionCookiesAsync(const DeleteCallback&) = 0;

  // Deletes all cookies in the store.
  void DeleteAllAsync(const DeleteCallback& callback);

  // Flush the backing store (if any) to disk and post the given callback when
  // done.
  virtual void FlushStore(const base::Closure& callback) = 0;

  // Protects session cookies from deletion on shutdown, if the underlying
  // CookieStore implemention is currently configured to store them to disk.
  // Otherwise, does nothing.
  virtual void SetForceKeepSessionState();

  // Add a callback to be notified when the set of cookies named |name| that
  // would be sent for a request to |url| changes. The returned handle is
  // guaranteed not to hold a hard reference to the CookieStore object.
  //
  // |callback| will be called when a cookie is added or removed. |callback| is
  // passed the respective |cookie| which was added to or removed from the
  // cookies and a boolean indicating if the cookies was removed or not.
  //
  // Note that |callback| is called twice when a cookie is updated: once for
  // the removal of the existing cookie and once for the adding the new cookie.
  //
  // Note that this method consumes memory and CPU per (url, name) pair ever
  // registered that are still consumed even after all subscriptions for that
  // (url, name) pair are removed. If this method ever needs to support an
  // unbounded amount of such pairs, this contract needs to change and
  // implementors need to be improved to not behave this way.
  //
  // The callback must not synchronously modify another cookie.
  virtual std::unique_ptr<CookieChangedSubscription> AddCallbackForCookie(
      const GURL& url,
      const std::string& name,
      const CookieChangedCallback& callback) = 0;

  // Returns true if this cookie store is ephemeral, and false if it is backed
  // by some sort of persistence layer.
  // TODO(nharper): Remove this method once crbug.com/548423 has been closed.
  virtual bool IsEphemeral() = 0;
  void SetChannelIDServiceID(int id);
  int GetChannelIDServiceID();

 protected:
  CookieStore();
  int channel_id_service_id_;
};

}  // namespace net

#endif  // NET_COOKIES_COOKIE_STORE_H_
