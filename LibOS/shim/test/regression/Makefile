c_executables = \
	abort \
	abort_multithread \
	attestation \
	bootstrap \
	bootstrap_pie \
	bootstrap_static \
	cpuid \
	dev \
	epoll_wait_timeout \
	eventfd \
	exec \
	exec_fork \
	exec_invalid_args \
	exec_same \
	exec_victim \
	exit \
	exit_group \
	fdleak \
	file_check_policy \
	file_size \
	fopen_cornercases \
	fork_and_exec \
	fstat_cwd \
	futex_bitset \
	futex_requeue \
	futex_timeout \
	futex_wake_op \
	getcwd \
	getdents \
	getsockopt \
	host_root_fs \
	init_fail \
	large_mmap \
	large_dir_read \
	mkfifo \
	mmap_file \
	mprotect_file_fork \
	multi_pthread \
	openmp \
	pipe \
	poll \
	poll_closed_fd \
	poll_many_types \
	ppoll \
	proc_common \
	proc_cpuinfo \
	proc_path \
	pselect \
	readdir \
	sched \
	select \
	shared_object \
	sigaction_per_process \
	sigaltstack \
	sighandler_reset \
	sighandler_sigpipe \
	signal_multithread \
	sigprocmask_pending \
	spinlock \
	stat_invalid_args \
	str_close_leak \
	syscall \
	system \
	tcp_ipv6_v6only \
	tcp_msg_peek \
	udp \
	unix \
	vfork_and_exec

cxx_executables = bootstrap_c++

manifests = \
	manifest \
	argv_from_file.manifest \
	attestation.manifest \
	echo.manifest \
	eventfd.manifest \
	exec_victim.manifest \
	exit_group.manifest \
	file_check_policy_allow_all_but_log.manifest \
	file_check_policy_strict.manifest \
	futex_bitset.manifest \
	futex_requeue.manifest \
	futex_wake_op.manifest \
	getdents.manifest \
	host_root_fs.manifest \
	init_fail.manifest \
	large_mmap.manifest \
	mmap_file.manifest \
	multi_pthread.manifest \
	multi_pthread_exitless.manifest \
	openmp.manifest \
	proc_path.manifest \
	sh.manifest \
	shared_object.manifest

exec_target = \
	$(c_executables) \
	$(cxx_executables) \
	argv_from_file.manifest \
	echo.manifest \
	file_check_policy_allow_all_but_log.manifest \
	file_check_policy_strict.manifest \
	multi_pthread_exitless.manifest \
	sh.manifest

target = \
	$(exec_target) \
	$(manifests)

clean-extra += clean-tmp

extra_rules = \
	-e 's:\$$(RA_CLIENT_SPID):$(if $(RA_CLIENT_SPID),$(RA_CLIENT_SPID),AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA):g' \
	-e 's:\$$(RA_CLIENT_LINKABLE):$(if $(RA_CLIENT_LINKABLE),$(RA_CLIENT_LINKABLE),0):g'

include ../../../../Scripts/Makefile.configs
include ../../../../Scripts/Makefile.manifest
include ../../../../Scripts/Makefile.Test

CFLAGS-bootstrap_static = -static
CFLAGS-bootstrap_pie = -fPIC -pie
CFLAGS-exec_same = -pthread
CFLAGS-shared_object = -fPIC -pie
CFLAGS-syscall += -I$(PALDIR)/../include -I$(PALDIR)/host/$(PAL_HOST) -I$(PALDIR)/../include/arch/$(ARCH)/Linux
CFLAGS-openmp = -fopenmp
CFLAGS-multi_pthread = -pthread
CFLAGS-exit_group = -pthread
CFLAGS-abort_multithread = -pthread
CFLAGS-eventfd = -pthread
CFLAGS-futex_bitset = -pthread
CFLAGS-futex_requeue = -pthread
CFLAGS-futex_wake_op = -pthread
CFLAGS-proc_common = -pthread
CFLAGS-spinlock += -I$(PALDIR)/../include/lib -I$(PALDIR)/../include/arch/$(ARCH) -pthread
CFLAGS-sigaction_per_process += -pthread
CFLAGS-signal_multithread += -pthread

CFLAGS-attestation += -I$(PALDIR)/../lib/crypto/mbedtls/crypto/include \
                      -I$(PALDIR)/host/Linux-SGX \
                      -I$(PALDIR)/../include/pal
LDLIBS-attestation += $(PALDIR)/../lib/crypto/mbedtls/install/lib/libmbedcrypto.a

%: %.c
	$(call cmd,csingle)

%: %.cpp
	$(call cmd,cxxsingle)

export PAL_LOADER = $(RUNTIME)/pal-$(PAL_HOST)
export PYTHONPATH=../../../../Scripts

.PHONY: regression
regression: $(target)
	$(RM) libos-regression.xml
	$(MAKE) libos-regression.xml

libos-regression.xml: test_libos.py $(call expand_target_to_token,$(target))
	python3 -m pytest --junit-xml $@ -v $<

.PHONY: clean-tmp
clean-tmp:
	$(RM) -r *.tmp *.cached *.manifest.sgx *~ *.sig *.token .cache __pycache__ libos-regression.xml testfile tmp/*
