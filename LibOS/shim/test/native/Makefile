c_executables = \
	alarm \
	brk \
	clone \
	condvar \
	cpuinfo \
	dir \
	divzero \
	dup \
	epoll \
	epoll_socket \
	errno \
	exec_fork \
	file \
	fork \
	fork_bomb \
	fork_exec \
	fs \
	futextest \
	get_time \
	helloworld \
	helloworld_pthread \
	kill \
	malloc \
	meminfo \
	msg_create \
	msg_create_libos \
	msg_send \
	msg_send_libos \
	multiproc \
	multisleep \
	pause \
	pid_alloc \
	pid_kill \
	pipe \
	pipe_latency \
	readdir \
	rename \
	script \
	sem \
	sleep \
	socketpair \
	sqrt \
	start \
	sync \
	system \
	tcp \
	test_start_pthread_m \
	time \
	vfork \
	vfork_exec

cxx_executables =

manifests = \
	manifest \
	exec_fork.manifest \
	ls.manifest \
	script.manifest \
	static.manifest

exec_target = \
	$(c_executables) \
	$(cxx_executables) \
	ls.manifest

target = \
	$(exec_target) \
	$(manifests)

include ../../../../Scripts/Makefile.configs
include ../../../../Scripts/Makefile.manifest
include ../../../../Scripts/Makefile.Test

CFLAGS-msg_create_libos += $(CFLAGS-libos)
CFLAGS-msg_send_libos += $(CFLAGS-libos)

LDLIBS-condvar += -lpthread
LDLIBS-futextest += -lpthread
LDLIBS-get_time += -lm
LDLIBS-helloworld_pthread += -lpthread
LDLIBS-msg_create_libos += -llibos
LDLIBS-msg_send_libos += -llibos
LDLIBS-sqrt += -lm
LDLIBS-start += -lpthread -lm
LDLIBS-sync += -lpthread
LDLIBS-test_start_pthread_m += -lm

%: %.c
	$(call cmd,csingle)

%: %.cpp
	$(call cmd,cxxsingle)

ifeq ($(filter %clean,$(MAKECMDGOALS)),)
include $(wildcard *.d)
endif
