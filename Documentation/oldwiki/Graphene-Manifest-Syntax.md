## Basic Syntax

A manifest file is an application-specific configuration text file that specifies the environment
and resources for running an application inside Graphene. A manifest file contains entries
separated by line breaks. Each configuration entry consists of a key and a value. Whitespaces
before/after the key and before/after the value are ignored. The value can be written in quotes,
indicating that the value should be assigned to this string verbatim. (The quotes syntax is useful
for values with leading/trailing whitespaces, e.g. `" SPACES! "`.) Each entry must be in the
following format:

    [Key][.Key][.Key] = [Value]  or  [Key][.Key][.Key] = "[Value]"

Comments can be inlined in a manifest by starting them with a sharp sign (`# comment`). Any text
after a sharp sign will be considered part of a comment and discarded while loading the manifest
file.

## Loader-related (Required by PAL)

### Executable

    loader.exec=[URI]

This syntax specifies the executable to be loaded into the library OS. The executable must be an
ELF binary, with an entry point defined to start its execution (i.e., the binary needs a `main()`
routine, it cannot just be a library).

### Preloaded Libraries (e.g., the LibOS library)

    loader.preload=[URI][,URI]...

This syntax specifies the libraries to be preloaded before loading the executable. The URIs of the
libraries must be separated by commas. The libraries must be ELF binaries.

### Executable Name

    loader.execname=[STRING]

This syntax specifies the executable name that will be passed as the first argument (`argv[0]`)
to the executable. If the executable name is not specified in the manifest, the PAL will use the
URI of the executable or the manifest -- depending on whether the executable or the manifest is
given as the first argument to the PAL loader -- as `argv[0]` when running the executable.

### Environment Variables

    loader.env.[ENVIRON]=[VALUE]

By default, the environment variables on the host will be passed to the library OS. Specifying an
environment variable using this syntax adds/overwrites it and passes to the library OS. This syntax
can be used multiple times to specify more than one environment variable. An environment variable
can be deleted by giving it an empty value.

### Debug Type

    loader.debug_type=[none|inline]
    (Default: none)

This specifies the debug option while running the library OS. If the debug type is `none`, no
debug output will be printed to standard output. If the debug type is `inline`, a dmesg-like
debug output will be printed inlined with standard output.


## System-related (Required by LibOS)

### Stack Size

    sys.stack.size=[# of bytes (with K/M/G)]

This specifies the stack size of each thread in each Graphene process. The default value is
determined by the library OS. Units like `K` (KB), `M` (MB), and `G` (GB) can be appended to the
values for convenience. For example, `sys.stack.size=1M` indicates a 1MB stack size.

### Program Break (Heap) Size

    sys.brk.size=[# of bytes (with K/M/G)]

This specifies the program break (brk) size in each Graphene process. The default value of the
program break size is determined by the library OS. Units like `K` (KB), `M` (MB), and `G` (GB) can
be appended to the values for convenience. For example, `sys.brk.size=1M` indicates a 1MB brk size.


## FS-related (Required by LibOS)

### Mount Points

    fs.mount.[identifier].path=[PATH]
    fs.mount.[identifier].type=[chroot|...]
    fs.mount.[identifier].uri=[URI]

This syntax specifies how file systems are mounted inside the library OS. At least one mount point
is required in the manifest, because at least the Glibc library must be mounted in the library OS.
