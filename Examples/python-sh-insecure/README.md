# Python multi-process example

This directory contains an example for running Python 3.6 on Ubuntu 18.04 with
spawned child processes, including the Makefile and templates for generating the
manifests. The application is tested on Ubuntu 18.04, with both normal Linux and
SGX platforms.

This example is *insecure*: the manifest file uses `sgx.allowed_files` to allow
all Python libraries/scripts without any integrity checks. This example simply
shows the functionality of Graphene but *does not* prevent the attacker from
silently modifying Python files. For secure Python usage, see the
`python-simple` example.

## Trick for Python -> Shell -> Python invocation

When Python script contains something like `os.system('python3 ...')`, the
application actually forks Python, the forked child performs `execve('sh')`, the
resulting shell forks again, and the final child performs `execve('python3')`.

This means that the chain of processes is Python -> Shell -> Python. This
contradicts the current way of specifying `sgx.trusted_children` in Graphene
manifests: the sh manifest must know the SGX measurement of Python, but Python
manifest must know the SGX measurement of sh. This creates an endless loop.

To break this loop, we use the trick of symlinks. Python3 already an actual
binary which is `/usr/bin/python3.6` and its symlink `/usr/bin/python3`. In the
Python script, we specify `python3` as the target. So the child of sh is
`python3`, and we can use `python3.6` as the first (main) binary in Graphene.
The loop thus becomes Python3.6 -> Shell -> Python3. *This is a hacky solution*;
Graphene manifest syntax will be re-worked to allow such chains in the future.

## Build

- without SGX: Run `make` (non-debug) or `make DEBUG=1` (debug) in the
  directory.

- with SGX: Run `make SGX=1` (non-debug) or `make SGX=1 DEBUG=1` (debug) in the
  directory.

## Run

- without SGX: `./pal_loader ./python3.6.manifest scripts/callprocess.py`

- with SGX: `SGX=1 ./pal_loader ./python3.6.manifest scripts/callprocess.py`
