## Basic Syntax

A manifest file is an application-specific configuration file that specifies the environment and
resources for running a Graphene library OS instance. A manifest file is a text file, containing
entries separated by _line breaks_. Each configuration entry consists of a key and a value.
Whitespaces before/after the key and before/after the value are ignored. The value can be written
in quotes, indicating that the value should be assigned to this string verbatim, or be unquoted.
Each entry must be in the following format:

    [Key][.Key][.Key] = [Value] or [Key][.Key][.Key] = "[Value]"

Comments can be inlined in a manifest, by preceding them with a _sharp sign (#)_. Any texts behind
a _sharp sign (#)_ will be considered part of a comment and be discarded while loading the manifest
file.

## Loader-related (Required by PAL)

### Executable (REQUIRED)

    loader.exec=[URI]

This syntax specifies the executable to be loaded into the library OS. The executable must be an
ELF binary, with a defined entry point to start its execution.

### Preloading Guest Libraries (e.g., LibOS)

    loader.preload=[URI][,URI]...

This syntax specifies the libraries to be preloaded before loading the executable. The URI of the
libraries will be separated by _commas(,)_. The libraries must be ELF binaries.

### Executable Name

    loader.execname=[STRING]

This syntax specifies the executable name that will be passed as the first argument to the
executable. If the executable name is not specified in the manifest, the PAL will use the URI
of the executable or manifest as the first argument when executing the executable. This is used
when the manifest is given as the first argument to the PAL loader.

### Environment Variables

    loader.env.[ENVIRON]=[VALUE]

By default, the environment variables on the host will be passed to the library OS. This syntax
specifies the environment variable values that are customized for the library OS. This syntax
can be used for multiple times to specify more than one environment variables, and the environment
variables can be deleted by giving a empty value.

### Debug Type (DEFAULT:none)

    loader.debug_type=[none|inline]

This specifies the debug option while running the library OS. If the debug type is _none_,
no debug output will be printed to the screen. If the debug type is _inline_, a dmesg-like debug
output will be printed inlined with standard output.


## System-related (Required by LibOS)

### Stack Size

    sys.stack.size=[# of bytes (with K/M/G)]

This specifies the stack size of each thread in each Graphene process. The default value is
determined by the library OS. Units like K (KB), M (MB), and G (GB) can be given to the values
for convenience. For example, `sys.stack.size=1M` indicates a 1MB stack size.

### Program Break (Heap) Size

    sys.brk.size=[# of bytes (with K/M/G)]

This specifies the program break (_brk_) size in each Graphene process. The default value of
program break size is determined by the library OS. Units like K (KB), M (MB), and G (GB) can be
given to the values for convenience. For example, `sys.brk.size=1M` indicates a 1MB max brk size.


## FS-related (Required by LibOS)

### Mount Points (REQUIRED)

    fs.mount.[identifier].path=[PATH]
    fs.mount.[identifier].type=[chroot|...]
    fs.mount.[identifier].uri=[URI]

This syntax specifies how the FSes are mounted inside the library OSes. This syntax is almost
required for all binaries, because the GNU Library C must be at least mounted somewhere in the
library OS.
