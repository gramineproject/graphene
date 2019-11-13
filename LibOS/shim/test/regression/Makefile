c_executables = \
	abort \
	abort_multithread \
	bootstrap \
	bootstrap_pie \
	bootstrap_static \
	cpuid \
	epoll_wait_timeout \
	eventfd \
	exec \
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
	large-mmap \
	large_dir_read \
	mmap-file \
	mprotect_file_fork \
	multi_pthread \
	openmp \
	poll \
	poll_many_types \
	ppoll \
	proc \
	proc-path \
	proc_cpuinfo \
	pselect \
	readdir \
	sched \
	select \
	shared_object \
	sigaltstack \
	sigprocmask \
	spinlock \
	stat_invalid_args \
	str_close_leak \
	syscall \
	tcp_ipv6_v6only \
	tcp_msg_peek \
	udp \
	unix \
	vfork_and_exec

cxx_executables = bootstrap-c++

manifests = \
	manifest \
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
	large-mmap.manifest \
	mmap-file.manifest \
	multi_pthread.manifest \
	multi_pthread_exitless.manifest \
	openmp.manifest \
	proc-path.manifest \
	shared_object.manifest

exec_target = \
	$(c_executables) \
	$(cxx_executables) \
	file_check_policy_strict.manifest \
	file_check_policy_allow_all_but_log.manifest \
	multi_pthread_exitless.manifest

target = \
	$(exec_target) \
	$(manifests)

clean-extra += clean-tmp

include ../../../../Scripts/Makefile.configs
include ../../../../Scripts/Makefile.manifest
include ../../../../Scripts/Makefile.Test

CFLAGS-bootstrap_static = -static
CFLAGS-bootstrap_pie = -fPIC -pie
CFLAGS-shared_object = -fPIC -pie
CFLAGS-syscall += -I$(PALDIR)/../include -I$(PALDIR)/host/$(PAL_HOST)
CFLAGS-openmp = -fopenmp
CFLAGS-multi_pthread = -pthread
CFLAGS-exit_group = -pthread
CFLAGS-abort_multithread = -pthread
CFLAGS-eventfd = -pthread
CFLAGS-futex_bitset = -pthread
CFLAGS-futex_requeue = -pthread
CFLAGS-futex_wake_op = -pthread
CFLAGS-spinlock += -I$(PALDIR)/../include/lib -pthread
CFLAGS-sigprocmask += -pthread

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
