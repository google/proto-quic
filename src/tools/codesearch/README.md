Chromium CodeSearch Library
===========================

The `codesearch` Python library provides an interface for talking to the
Chromium CodeSearch backend at https://cs.chromium.org/

The primary entry point into the library is the `CodeSearch` class. Various
message classes you are likely to encounter are defined in `messages.py`.

A quick example:

```py
import codesearch

# The plugin needs to locate a local Chromium checkout. We are passing '.' as a
# path inside the source directory, which works if the current directory is
# inside the Chromium checkout.
cs = codesearch.CodeSearch(a_path_inside_source_dir='.')

# The backend takes CompoundRequests ...
results = cs.SendRequestToServer(codesearch.CompoundRequest(
    search_request=[
        codesearch.SearchRequest(query='hello world')
    ]))

# ... and returns a CompoundResponse
assert isinstance(results, codesearch.CompoundResponse)

# both CompoundRequest and CompoundResponse are documented in messages.py.

for search_result in results.search_response[0].search_result:
    assert isinstance(search_result, codesearch.SearchResult)

    if not hasattr(search_result, 'snippet'):
        continue

    for snippet in search_result.snippet:
        assert isinstance(snippet, codesearch.Snippet)

	# Just print the text of the search result snippet.
        print snippet.text.text
```

NOTE: This isn't quite production quality code and the infra folks may pull the rug
from under the library at any point.

If you run into any bugs, or you'd like to contribute, please let someone in the
`OWNERS` file know.

