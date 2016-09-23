# SDCH 

"SDCH" stands for "Shared Dictionary Compression over HTTP".  It is a
protocol for compressing URL responses used when the server and
the client share a dictionary that can be referred to for
compression/encoding and decompression/decoding.  The details of the
SDCH protocol are specified in 
[the spec](https://docs.google.com/a/chromium.org/document/d/1REMkwjXY5yFOkJwtJPjCMwZ4Shx3D9vfdAytV_KQCUo/edit?pli=1)
(soon to be moved to github) but in brief:

1. If the client supports SDCH decoding, it advertises "sdch" in the
   "Accept-Encoding" header.
2. If the server could have encoded a response with a dictionary (but
   didn't, because the client didn't have the dictionary), it includes
   an advisory "Get-Dictionary: <url>" header in its response.
3. If the client has a dictionary that the server has previously
   advertised as being usable for encoding a particular requests, it
   advertises that dictionary as being available via an
   "Avail-Dictionary: <hash>" header in the request.
4. If the server chooses to encode a response with a dictionary, it
   includes "sdch" in a "Content-Encoding" header, in which case the
   body will reference the dictionary to be used for decoding (which
   must be one the client advertised in the original request).
   Encodings may be chained; often responses are SDCH encoded, and then
   gzip encoded.

## SDCH in Chromium: Overview

The SDCH implementation in Chromium is spread across several classes
in several different directories:

* SdchManager (in net/base): This class contains all
  dictionaries currently known to Chromium.  Each URLRequestContext
  points to an SdchManager; at the chrome/ level, there is one
  SdchManager per profile.  URLRequestHttpJob consults the SdchManager
  for what dictionaries should be advertised with a URLRequest, and
  notifies the SdchManager whenever it sees a "Get-Dictionary"
  header.  The SdchManager does *not* mediate fetching of
  dictionaries; it is conceptually layered underneath URLRequest and
  has no knowledge of URLRequests.  There are several nested classes of
  SdchManager (Dictionary, DictionarySet) used in the SDCH
  implementation; see sdch_manager.h for details.
* SdchObserver (in net/base).  This is an Abstract Base
  Class which other classes may implement if those classes wish to
  receive notifications about SDCH events.  Such classes should also
  register as observers with the SdchManager.
* SdchFilter (int net/filter).  This class is derived from net::Filter
  that is used for decoding the SDCH response; it cooperates with
  SdchManager and the URLRequestJob to decode SDCH encoded responses. 
* SdchDictionaryFetcher (int net/url_request):
  This class implements the nuts&bolts of fetching an SDCH
  dictionary.  
* SdchOwner (in net/sdch): This class is an SdchObserver.
  It contains policy for the SDCH implementation, including mediation
  of fetching dictionaries, prioritization and eviction of
  dictionaries in response to new fetches, and constraints on the
  amount of memory that is usable by SDCH dictionaries.  It initiates
  dictionary fetches as appropriate when it receives notification of
  a "Get-Dictionary" header from the SdchManager.

A net/ embedder should instantiate an SdchManager and an SdchOwner,
and guarantee that the SdchManager outlive the SdchOwner.

Note the layering of the above classes:

1. The SdchManager class has no knowledge of URLRequests.  URLRequest
   is dependent on that class, not the reverse.
2. SdchDictionaryFetcher is dependent on URLRequest, but is still a
   utility class exported by the net/ library for use by higher levels.
3. SdchOwner manages the entire system on behalf of the embedder.  The
   intent is that the embedder can change policies through methods on
   SdchOwner, while letting the SdchOwner class take care of policy
   implementation. 

## SDCH in Chromium: Debugging

Data that is useful in debugging SDCH problems:

* The SDCH UMA prefix is "Sdch3", and histograms that have been found
  useful for debugging include 
    * ProblemCodes_* (though this requires trawling the source for each bucket).
    * ResponseCorruptionDetection.{Cached,Uncached}: An attempt to make
      sense of the twisted mess in SdchFilter::ReadFilteredData mentioned
      above. 
    * BlacklistReason: Why requests avoid using SDCH when they could use
      it. 
* about:net-internals has an SDCH tab, showing loaded dictionaries and
  other information.  Searching in net-internals for "Get-Dictionary",
  the URLRequest that actually fetches that dictionary, and then the
  hash of that dictionary (often used as the file name) can also be
  useful.

## SDCH in Chromium: Gotchas and corner cases

There are a couple of known issues in SDCH in Chromium that developers
in this space should be aware of:

* As noted in the spec above, there have historically been problems
  with middleboxes stripping or corrupting SDCH encoded responses.
  For this reason, the protocol requires that if a server is not using
  SDCH encoding when it has previously advertised the availability of
  doing such, it includes an "X-SDCH-Encode: 0" header in the
  response.  Servers don't always do this (especially multi-servers),
  and that can result in failed decodings and requests being dropped
  on the floor.  The code to handle this is a twisted mess (see
  SdchFilter::ReadFilteredData()) and problems have often been seen
  from or associated with it.
* If the decoding logic trips over a problem, it will often blacklist
  the server in question, temporarily (if it can recover that request)
  or permanently (if it can't).  This can lead to a mysterious lack of
  SDCH encoding when it's expected to be present.
* The network cache currently stores the response precisely as received from
  the network.  This means that requests that don't advertise SDCH
  may get a cached value that is SDCH encoded, and requests that do
  advertise SDCH may get a cached value that is not SDCH encoded.
  The second case is handled transparently, but the first case may
  lead to request failure. 

