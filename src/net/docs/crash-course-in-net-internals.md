# A Crash Course in Debugging with about:net-internals

This document is intended to help get people started debugging network errors
with about:net-internals, with some commonly useful tips and tricks.  This
document is aimed more at how to get started using some of its features to
investigate bug reports, rather than as a feature overview.

It would probably be useful to read
[life-of-a-url-request.md](life-of-a-url-request.md) before this document.

# What Data Net-Internals Contains

about:net-internals provides a view of browser activity from net/'s perspective.
For this reason, it lacks knowledge of tabs, navigation, frames, resource types,
etc.

The top level network stack object is the URLRequestContext.  The Events View
has information for all Chrome URLRequestContexts that are hooked up to the
single, global, ChromeNetLog object.  This includes both incognito and non-
incognito profiles, among other things.  The Events view only shows events for
the period that net-internals was open and running, and is incrementally updated
as events occur.  The code attempts to add a top level event for URLRequests
that were active when the tab was opened, to help debug hung requests, but
that's best-effort only, and only includes requests for the current profile and
the system URLRequestContext.

The other views are all snapshots of the current state of the main
URLRequestContext's components, and are updated on a 5 second timer.  These will
show objects that were created before about:net-internals was opened.  Most
debugging is done with the Events view (which will be all this document
covers), but it's good to be aware of this distinction.

# Events vs Sources

The Event View shows events logged by the NetLog.  The NetLog model is that
long-lived network stack objects, called sources, emit events over their
lifetime.  When looking at the code, a "NetLogWithSource" object contains a source
ID, and a pointer to the NetLog the source emits events to.  Some events have a
beginning and end point (during which other subevents may occur), and some only
occur at a single point in time.  Generally only one event can be occuring for a
source at a time.  If there can be multiple events doing completely independent
thing, the code often uses new sources to represent the parallelism.

"Sources" correspond to certain net objects, however, multiple layers of net/
will often log to a single source.  Here are the main source types and what they
include (Excluding HTTP2 [SPDY]/QUIC):

* URL_REQUEST:  This corresponds to the URLRequest object.  It includes events
from all the URLRequestJobs, HttpCache::Transactions, NetworkTransactions,
HttpStreamFactoryImpl::Requests, HttpStream implementations, and
HttpStreamParsers used to service a response.  If the URL_REQUEST follows HTTP
redirects, it will include each redirect.  This is a lot of stuff, but generally
only object is doing work at a time.  This event source includes the full URL
and generally includes the request / response headers (Except when the cache
handles the response).

* HTTP_STREAM_JOB:  This corresponds to HttpStreamFactoryImpl::Job (Note that
one Request can have multiple Jobs).  It also includes its proxy and DNS
lookups.  HTTP_STREAM_JOB log events are separate from URL_REQUEST because
two stream jobs may be created and races against each other, in some cases -
one for one for QUIC, and one for HTTP.  One of the final events of this source
indicates how an HttpStream was created (Reusing an existing SOCKET /
HTTP2_SESSION / QUIC_SESSION, or creating a new one).

* \*_CONNECT_JOB:  This corresponds to the ConnectJob subclasses that each socket
pool uses.  A successful CONNECT_JOB return a SOCKET.  The events here vary a
lot by job type.  Their main event is generally either to create a socket, or
request a socket from another socket pool (Which creates another CONNECT_JOB)
and then do some extra work on top of that - like establish an SSL connection on
top of a TCP connection.

* SOCKET:  These correspond to TCPSockets, but may also have other classes
layered on top of them (Like an SSLClientSocket).  This is a bit different from
the other classes, where the name corresponds to the topmost class, instead of
the bottommost one.  This is largely an artifact of the fact the socket is
created first, and then SSL (Or a proxy connection) is layered on top of it.
SOCKETs may be reused between multiple requests, and a request may end up
getting a socket created for another request.

* HOST_RESOLVER_IMPL_JOB:  These correspond to HostResolverImpl::Job.  The
include information about how long the lookup was queued, each DNS request that
was attempted (With the platform or built-in resolver) and all the other sources
that are waiting on the job.

When one source depends on another, the code generally logs an event with
"source_dependency" value to both sources, which lets you jump between the two
related events.

# Debugging

When you receive a report from the user, the first thing you'll generally want
to do find the URL_REQUEST[s] that are misbehaving.  If the user gives an ERR_*
code or the exact URL of the resource that won't load, you can just search for
it.  If it's an upload, you can search for "post", or if it's a redirect issue,
you can search for "redirect".  However, you often won't have much information
about the actual problem.  There are two filters in net-internals that can help
in a lot of cases:

* "type:URL_REQUEST is:error" will restrict the list to URL_REQUEST object with
an error of some sort (red background).  Cache errors are often non-fatal, so
you should generally ignore those, and look for a more interesting one.

* "type:URL_REQUEST sort:duration" will show the longest-lived requests first.
This is often useful in finding hung or slow requests.

For a list of other filter commands, you can mouse over the question mark on
about:net-internals.

Once you locate the problematic request, the next is to figure out where the
problem is - it's often one of the last events, though it could also be related
to response or request headers.  You can use "source_dependency" links to drill
down into other related sources, or up from layers below URL_REQUEST.

You can use the name of an event to search for the code responsible for that
event, and try to deduce what went wrong before/after a particular event.  Note
that the event names used in net-internals are not the entire string names, so
you should not do an entire string match.

Some things to look for while debugging:

* CANCELLED events almost always come from outside the network stack.

* Changing networks and entering / exiting suspend mode can have all sorts of
fun and exciting effects on underway network activity.  Network changes log a
top level NETWORK_CHANGED event with no source - the event itself is treated as
its own source.  Suspend events are currently not logged.

* URL_REQUEST_DELEGATE / DELEGATE_INFO events mean a URL_REQUEST is blocked on a
URLRequest::Delegate or the NetworkDelegate, which are implemented outside the
network stack.  A request will sometimes be CANCELED here for reasons known only
to the delegate.  Or the delegate may cause a hang.  In general, to debug issues
related to delegates, one needs to figure out which method of which object is
causing the problem.  The object may be the a NetworkDelegate, a
ResourceThrottle, a ResourceHandler, the ResourceLoader itself, or the
ResourceDispatcherHost.

* Sockets are often reused between requests.  If a request is on a stale
(reused) socket, what was the previous request that used the socket, how long
ago was it made?

* SSL negotation is a process fraught with peril, particularly with broken
proxies.  These will generally stall or fail in the SSL_CONNECT phase at the
SOCKET layer.

* Range requests have magic to handle them at the cache layer, and are often
issued by the media and PDF code.

* Late binding:  HTTP_STREAM_JOBs are not associated with any CONNECT_JOB until
a CONNECT_JOB actually connects.  This is so the highest priority pending job
gets the first available socket (Which may be a new socket, or an old one that's
freed up).  For this reason, it can be a little tricky to relate hung
HTTP_STREAM_JOBs to CONNECT_JOBs.

* Each CONNECT_JOB belongs to a "group", which has a limit of 6 connections.  If
all CONNECT_JOBs beling to a group (The CONNECT_JOB's description field) are
stalled waiting on an available socket, the group probably has 6 sockets that
that are hung - either hung trying to connect, or used by stalled requests and
thus outside the socket pool's control.

* There's a limit on number of DNS resolutions that can be started at once.  If
everything is stalled while resolving DNS addresses, you've probably hit this
limit, and the DNS lookups are also misbehaving in some fashion.

# Miscellany

These are just miscellaneous things you may notice when looking through the
logs.

* URLRequests that look to start twice for no obvious reason.  These are
typically main frame requests, and the first request is AppCache.  Can just
ignore it and move on with your life.

* Some HTTP requests are not handled by URLRequestHttpJobs.  These include
things like HSTS redirects (URLRequestRedirectJob), AppCache, ServiceWorker,
etc.  These generally don't log as much information, so it can be tricky to
figure out what's going on with these.

* Non-HTTP requests also appear in the log, and also generally don't log much
(blob URLs, chrome URLs, etc).

* Preconnects create a "HTTP_STREAM_JOB" event that may create multiple
CONNECT_JOBs (or none) and is then destroyed.  These can be identified by the
"SOCKET_POOL_CONNECTING_N_SOCKETS" events.
