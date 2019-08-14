# SGX: Application Won't Start

If you are using an application with a fixed mapping, and at a relatively low address (say 64K), you may have problems starting an enclave on newer versions of Ubuntu.  Check:

sudo sysctl vm.mmap_min_addr

If the result is non-zero, try setting it to zero:

sudo sysctl vm.mmap_min_addr=0
