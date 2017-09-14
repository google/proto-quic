# Network Traffic Annotations List
This file describes the `tools/traffic_annotation/summary/annotations.xml`.

# Content Description
`annotations.xml` includes the summary of all network traffic annotations in
Chromium repository. The content includes complete annotations and the merged
partial and completing (and branched completing) annotations.
For each annotation, unique id, hash code of unique id, hash code of the
content, and the list of OSes using this annotation is presented. If annotation
is a reserved one, instead of content hash code, a `reserved` attribute is
included.
Once an annotation is removed from the repository, a `deprecated` attribute is
added to its item in this file, with value equal to the deprecation date.
These items can be manually or automatically pruned after sufficient time.

# How to Generate/Update.
Run `traffic_annotation_auditor` to check for annotations correctness and
automatic update. After each modification of`annotations.xml`, auditor calls
`tools/traffic_annotation/scripts/annotations_xml_downstream_updater.py` to
update all users of this file.
