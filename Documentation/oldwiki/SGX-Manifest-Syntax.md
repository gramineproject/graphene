# SGX Manifest Syntax
The basic manifest syntax is described in [[Manifest Syntax]]. The SGX-specific syntax in a manifest is ignored if Graphene library OS is run without Intel SGX support. All keys in the SGX-specific syntax are optional. If the keys are not specified, Graphene library OS will use the default values.

## Basic SGX-specific Syntax

### Enclave size (OPTIONAL)
    sgx.enclave_size=[SIZE]
    (default: 256M)
This syntax specifies the enclave size to be created. Beside PAL and library OS, the remaining memory in the enclave is used as the heap, to load application libraries or create anonymous memory. The application cannot allocate memory that exceeds the enclave size.

### Thread number (OPTIONAL)
    sgx.thread_num=[NUM]
    (Default: 4)
This syntax specifies the number of threads that can be created inside the enclave. The application cannot create more threads than this limit. Creating more threads will require more enclave memory.

### Debugging (OPTIONAL)
    sgx.debug=[1|0]
    (Default: 1)
This syntax specifies the whether the enclave can be debugged. Currently Graphene library OS only supports the debugging mode.

### ISV Product ID and SVN (OPTIONAL)
    sgx.isvprodid=[NUM]
    sgx.isnsvn=[NUM]
    (Default: 0)
This syntax specifies the ISV Product ID and SVN to be added into the enclave signature.

## Trusted files and child processes

### Trusted Files (OPTIONAL)
    sgx.trusted_files.[identifier]=[URI]
This syntax specifies the files that have to be signed, and thus are allowed to be loaded into the enclave. The signer tool will automatically generate the checksums of these files and add them into the SGX-specific manifest (`.manifest.sgx`).

### Allowed Files (OPTIONAL)
    sgx.allowed_files.[identifier]=[URI]
This syntax specifies the files that are allowed to be loaded into the enclave unconditionally. These files will be not signed, so it is insecure if these files are loaded as code or contain critical information. Developers must not allow files blindly.

### Trusted Child Processes (OPTIONAL)
    sgx.trusted_children.[identifier]=[URI of signature (.sig)]
This syntax specifies the signatures that are allowed to be created as child processes of the current application. Upon process creation, the current enclave will perform attest the enclave in the child process, against the trusted signatures. If the child process is not trusted, the current enclave will not communicate with it. 