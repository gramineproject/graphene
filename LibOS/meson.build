subdir('shim')

glibc_libs = [
    'glibc-build/csu/crt1.o',
    'glibc-build/csu/crti.o',
    'glibc-build/csu/crtn.o',
    'glibc-build/dlfcn/libdl.so.2',
    'glibc-build/libc.so',
    'glibc-build/libc.so.6',
    'glibc-build/login/libutil.so.1',
    'glibc-build/math/libm.so.6',
    'glibc-build/nis/libnsl.so.1',
    'glibc-build/nptl/libpthread.so.0',
    'glibc-build/nptl_db/libthread_db.so.1',
    'glibc-build/nss/libnss_compat.so.2',
    'glibc-build/nss/libnss_db.so.2',
    'glibc-build/nss/libnss_files.so.2',
    'glibc-build/resolv/libanl.so.1',
    'glibc-build/resolv/libnss_dns.so.2',
    'glibc-build/resolv/libresolv.so.2',
    'glibc-build/rt/librt.so.1',
]

gcc_libs = []

if host_machine.cpu_family() == 'x86_64'
    glibc_libs += 'glibc-build/elf/ld-linux-x86-64.so.2'
    glibc_libs += 'glibc-build/mathvec/libmvec.so.1'
#   gcc_libs += 'gcc-build/x86_64-pc-linux-gnu/libgomp/.libs/libgomp.so.1'
endif

install_data(glibc_libs + gcc_libs,
    install_dir: join_paths(pkglibdir, 'runtime', 'glibc'))
