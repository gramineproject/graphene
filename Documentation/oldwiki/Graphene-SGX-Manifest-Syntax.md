The basic manifest syntax for Graphene is described in [[Graphene Manifest Syntax]]. If Graphene
is *not* running with SGX, the SGX-specific syntax is ignored. All keys in the SGX-specific syntax
are optional. If the keys are not specified, Graphene will use the default values.

## Basic SGX-specific Syntax

### Enclave Size

    sgx.enclave_size=[SIZE]
    (default: 256M)

This syntax specifies the size of the enclave set during enclave creation time (recall that SGX v1
requires a predetermined maximum size of the enclave). The PAL and library OS code/data count
towards this size value, as well as the application memory itself: application's code, stack, heap,
loaded application libraries, etc. The application cannot allocate memory that exceeds this limit.

### Number of Threads

    sgx.thread_num=[NUM]
    (Default: 4)

This syntax specifies the maximum number of threads that can be created inside the enclave (recall
that SGX v1 requires a predetermined maximum number of thread slots). The application cannot have
more threads than this limit *at a time* (however, it is possible to create new threads after old
threads are destroyed).

### Debug/Production Enclave

    sgx.debug=[1|0]
    (Default: 1)

This syntax specifies whether the enclave can be debugged. Set it to 1 for a debug enclave and to 0
for a production enclave.

### ISV Product ID and SVN

    sgx.isvprodid=[NUM]
    sgx.isnsvn=[NUM]
    (Default: 0)

This syntax specifies the ISV Product ID and SVN to be added to the enclave signature.

## Trusted Files and Child Processes

### Trusted Files

    sgx.trusted_files.[identifier]=[URI]

This syntax specifies the files to be cryptographically hashed, and thus allowed to be loaded
into the enclave. The signer tool will automatically generate hashes of these files and add them
into the SGX-specific manifest (`.manifest.sgx`). This is especially useful for shared libraries:
a trusted library cannot be silently replaced by a malicious host because the hash verification
will fail.

### Allowed Files

    sgx.allowed_files.[identifier]=[URI]

This syntax specifies the files that are allowed to be loaded into the enclave unconditionally.
These files are not cryptographically hashed and are thus not protected. It is insecure to allow
files containing code or critical information; developers must not allow files blindly!

### File Check Policy

    sgx.file_check_policy=[strict|allow_all_but_log]
    (Default: strict)

This syntax specifies the file check policy, determining the behavior of authentication when
opening files.
By default, only files explicitly listed as _trusted_files_ or _allowed_files_ declared in the
manifest are allowed for access. If the file check policy is `allow_all_but_log`, all files other
than trusted and allowed are allowed for access, and Graphene-SGX emits a warning message for
every such file. This is a convenient way to determine the set of files that the ported
application uses.

### Trusted Child Processes

    sgx.trusted_children.[identifier]=[URI of signature (.sig)]

This syntax specifies the signatures of allowed child processes of the current application. Upon
process creation, the enclave in the current (parent) process will attest the enclave in the child
process, by comparing to the signatures of the trusted children. If the child process is not
trusted, the enclave will refuse to communicate with it.
