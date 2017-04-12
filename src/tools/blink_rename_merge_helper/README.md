Tool to help manage merge conflicts from the Blink rename. The tool is committed
into the Chromium repository. However, with the exception of the `run.py` loader
stub, everything else is fetched from the chromium-blink-rename Google Storage
bucket at runtime.

COMPONENTS is a list of component names and hashes; the tool always fetches the
latest COMPONENTS manifest from Google Storage. The checked-in copy exists as a
reference, so that changes can be reviewed and tracked. In addition, if the
component name is of the form `name-platform`, `name` is used as the actual
component name, while `platform` is passed to `download_from_google_storage.py`
as the platform argument. This is used to version per-platform binaries.

Use `upload_to_google_storage.py -b chromium-blink-rename -a pylib` to upload
new versions of the pylib.
