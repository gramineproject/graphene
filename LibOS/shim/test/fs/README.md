Test purpose
------------

These tests perform common FS operations in various ways to exercise the Graphene FS subsystem:

- open/close
- read/write
- create/delete
- read/change size
- seek/tell
- memory-mapped read/write
- sendfile
- copy directory in different ways

How to execute
--------------

Run `make fs-test` to only test regular files.
Run `make pf-test` to test regular files and protected files.
Run `make tmpfs-test` to test files and folders at a path on tmpfs.
Run `make test` to test all of the above.

(SGX only) Protected file tests assume that the SGX tools were installed in this directory:

```
cd $graphene/Pal/src/host/Linux-SGX/tools
make install PREFIX=$graphene/LibOS/shim/test/fs
```
