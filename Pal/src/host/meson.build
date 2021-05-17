subdir('Linux-common')
if skeleton
    subdir('Skeleton')
endif
if direct
    subdir('Linux')
endif
if sgx
    subdir('Linux-SGX')
endif

# this is for linking, when you have to "link against libpal.so" -- you can do this against any pal
if skeleton
    libpal_dep = libpal_skeleton_dep
elif direct
    libpal_dep = libpal_direct_dep
elif sgx
    libpal_dep = libpal_sgx_dep
endif
