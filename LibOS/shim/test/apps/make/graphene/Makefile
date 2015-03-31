SRCDIR = LibOS/shim/src

all:
	[ ! -d $(SRCDIR) ] || $(MAKE) $(if $(NPROC),-j$(NPROC),) -C $(SRCDIR)

clean:
	[ ! -d $(SRCDIR) ] || $(MAKE) -C $(SRCDIR) clean
