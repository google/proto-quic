# CQ Client Library.

This directory contains CQ client library to be distributed to other repos. If
you need to modify some files in this directory, please make sure that you are
changing the canonical version of the source code and not one of the copies,
which should only be updated as a whole using Glyco (when available, see
[chromium issue 489420](http://crbug.com/489420)).

The canonical version is located at
[https://chrome-internal.googlesource.com/infra/infra_internal/+/master/commit_queue/cq_client]().

When modifying cq.proto, consider adding checks to validator in
[https://chrome-internal.googlesource.com/infra/infra_internal/+/master/appengine/commit_queue/src/commitqueue/validate.go]().


## Generation of Python and Go bindings

### tl;dr
  
    make


### Details

All commands below assume you are working in a standard infra_internal gclient
checkout (e.g., after you ran `mkdir src && cd src && fetch infra_internal`) and
are in current directory of this README.md (that is, in
`cd infra_internal/commit_queue/cq_client`).

To generate Python's `cq_pb2.py` you'll need to get and `protoc` of version
**2.6.1**. You can get it by `make py-prepare`.
    
    make py

To generate Golang's protobuf file `cq.pb.go`, you'll need to bootstrap
infra/infra repository and go utilities `make go-prepare`.

    make go

## Notes

1. Please make sure to use proto3-compatible yntax, e.g. no default
values, no required fields. As of this writing (Jan 2016),
the Go protobuf compiler has been upgraded to 3.0.0. So, if you can generate go
bindings, all is good.

2. If after generating Python binding, CQ tests fail with:

        TypeError: __init__() got an unexpected keyword argument 'syntax'

You've probably used 3.0.0 protoc generator. We should eventually switch to 3x
Python version as well, but it requires upgrading infra's Python ENV to newer
package. See [bootstrap/README.md](../../bootstrap/README.md) for more
information.  We may end up deprecating Python before all infra's Python code
can be moved to protobuf v3.
