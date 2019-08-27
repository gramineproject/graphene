## Basic Syntax

A manifest file is an application-specific configuration file that specifies the environment and resources for running a Graphene library OS instance. A manifest file is a text file containing entries separated by _line breaks_. Each configuration entries must be in the following format: _(Spaces/Tabs before the first key and before/after the equal mark are ignored.)_

    [Key][.Key][.Key] = [Value]

Comments can be inlined in a manifest, by preceding them with a _sharp sign (#)_. Any texts behind a _sharp sign (#)_ will be considered part of a comment and be discarded while loading the manifest file.

## Loader-related (required by PAL)

### Executable (REQUIRED)
    loader.exec=[URI]
This syntax specifies the executable to be loaded into the library OS. The executable must be an ELF-format binary, with a defined entry point to start its execution.

### Preloaded libraries
    loader.preload=[URI][,URI]...
This syntax specifies the libraries to be preloaded before loading the executable. The URI of the libraries will be separated by _commas(,)_. The libraries must be ELF-format binaries, and may or may not have a defined entry point. If the libraries have their entry points, the entry points will be executed before jumping to the entry point of the executable, in the order as they are listed.  

### Executable name
    loader.execname=[STRING]
This syntax specifies the executable name given as the first argument to the binaries (the executable and preloaded libraries). If the executable name is not specified in the manifest, PAL will use the URI of the executable or manifest as the first argument when executing the executable. In some circumstance, the executable name has to be specified so the binaries can re-execute the executable or determine their functionalities. 

### Environment variables
    loader.env.[ENVIRON]=[VALUE]
By default, the environment variables on the host will be passed to the binaries in the library OSes. This syntax specifies the environment variable values that are customized for the library OSes. This syntax can be used for multiple times to specify more than one environment variables, and the environment variables can be deleted by giving a empty value.  

### Debug Type (DEFAULT:none)
    loader.debug_type=[none|inline]
This syntax specifies the debug option while executing the library OSes. If the debug type is _none_, no debug output will be printed to the screen. If the debug type is _inline_, a dmesg-like debug output will be printed inlined with standard output.


## System-related (required by LibOS)

### Stack size
    sys.stack.size=[# of bytes]
This syntax specifies the stack size of the first thread in each Graphene process. The default value of stack size is determined by the library OSes.

### Program break size
    sys.brk.size=[# of bytes]
This syntax specifies the program break (_brk_) size in each Graphene process. The default value of program break size is determined by the library OSes.


## FS-related (required by LibOS)

### Mount points (REQUIRED)
    fs.mount.[identifier].path=[PATH]
    fs.mount.[identifier].type=[chroot|...]
    fs.mount.[identifier].uri=[URI]
This syntax specifies how the FSes are mounted inside the library OSes. This syntax is almost required for all binaries, because the GNU Library C must be at least mounted somewhere in the library OSes.
