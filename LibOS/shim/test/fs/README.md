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

- `make test` to run all tests
- `make fs-test` to test regular files
- `make tmpfs-test` to test tmpfs (temporary in-memory) files
- `make pf-test` to test protected files (SGX only)

(SGX only) Protected file tests assume that the SGX tools were installed in this directory:

```
cd $graphene/Pal/src/host/Linux-SGX/tools
make install PREFIX=$graphene/LibOS/shim/test/fs
```
