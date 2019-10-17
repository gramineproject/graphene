Test purpose
------------

These tests perform common FS operations in various ways to exercise the Graphene FS subsystem:

- open/close
- read/write
- create/delete
- read/change size
- seek/tell
- memory-mapped read/write
- copy directory in different ways

How to execute
--------------

Run `make test` (tests both regular files and protected files).
Run `make fs-test` to only test regular files.
