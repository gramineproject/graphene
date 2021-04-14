graphene_lib = .lib/graphene-lib.a
pal_lib = $(RUNTIME_DIR)/libpal-$(PAL_HOST).so

.PHONY: all
all: graphene_lib_recurse

.PHONY: graphene_lib_recurse
graphene_lib_recurse:
	CFLAGS="-DIN_SHIM" $(MAKE) -C ../../../common/src target=$(abspath .lib)/

.PHONY: clean
clean:
	$(RM) -r .lib

.PHONY: distclean
distclean: clean
