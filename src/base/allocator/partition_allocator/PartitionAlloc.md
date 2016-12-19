# PartitionAlloc Design

This document explains a high-level design of PartitionAlloc.
If you're interested in its in-depth implementation, see comments
in PartitionAlloc.h.

[TOC]

## Overview

PartitionAlloc is a memory allocator optimized for performance and security
in Blink. All objects in Blink are expected to be allocated with
PartitionAlloc or Oilpan (but not yet done).

## Partitions and buckets

PartitionAlloc has three partitions. A partition is a heap that contains
certain types of objects. Specifically, PartitionAlloc allocates objects
on either of the following three partitions depending on their types:

* LayoutObject partition: A partition to allocate LayoutObjects.

* Buffer partition: A partition to allocate objects that have a strong risk
that the length and/or the contents are exploited by user scripts.
Specifically, Vectors, HashTables, ArrayBufferContents and Strings are
allocated on the Buffer partition.

* FastMalloc partition: A partition to allocate all other objects.
Objects marked with USING_FAST_MALLOC are allocated on the FastMalloc partition.

Each partition holds multiple buckets. A bucket is a region in a partition
that contains similar-sized objects. Each object allocation must be aligned
with the closest bucket size. For example, if a partition has three buckets
for 64 bytes, 256 bytes and 1024 bytes, then an object of 128 bytes is
rounded up to 256 bytes and allocated on the second bucket.

The LayoutObject partition has buckets for all N * sizeof(void*) (N = 1, 2, ..., N_max).
This means that no extra padding is needed to allocate a LayoutObject object.
Different sizes of LayoutObjects are allocated in different buckets.

The Buffer partition and the FastMalloc partition have many buckets.
They support any arbitrary size of allocations but padding may be added
to align the allocation with the closest bucket size. The bucket sizes are
chosen to keep the worst-case memory overhead less than 10%.

Large allocations (> 1 MB) are realized by direct memory mmapping.

## Performance

PartitionAlloc doesn't acquire a lock when allocating on the LayoutObject
partition, because it's guaranteed that LayoutObjects are allocated
only by the main thread.

PartitionAlloc acquires a lock when allocating on the Buffer partition and
the FastMalloc partition. PartitionAlloc uses a spin lock because thread contention
would be rare in Blink.

PartitionAlloc is designed to be extremely fast in fast paths. Just two
(reasonably predictable) branches are required for the fast paths of an
allocation and deallocation. The number of operations in the fast paths
is minimized, leading to the possibility of inlining.

Having a dedicated partition for LayoutObjects is helpful to improve cache
locality and thus help improve performance.

## Security

Security is one of the most important goals of PartitionAlloc.

Different partitions are guaranteed to exist in separate address spaces.
When objects contained in a page in a partition are all freed,
the physical memory is returned to the system but the address space
remains reserved. The address space may be reused later only for the partition.
Remember that PartitionAlloc puts LayoutObjects into a dedicated partition.
This is because LayoutObjects are likely to be a source of use-after-free.
Simiarly, PartitionAlloc puts Strings, Vectors etc into the Buffer partition
because the length and/or contents may be exploited by user scripts.
This means that PartitionAlloc greedily uses virtual address spaces in favor of
security hardening.

Also the following security properties are provided:

* Linear overflows cannot corrupt into the partition.

* Linear overflows cannot corrupt out of the partition.

* Metadata is recorded in a dedicated region (not next to each object).
Linear overflow or underflow cannot corrupt the metadata.

* Buckets are helpful to allocate different-sized objects on different addresses.
One page can contain only similar-sized objects.

* Dereference of a freelist pointer should fault.

* Partial pointer overwrite of freelist pointer should fault.

* Large allocations are guard-paged at the beginning and end.
