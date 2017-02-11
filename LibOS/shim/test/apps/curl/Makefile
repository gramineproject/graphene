manifests = curl.manifest

target =
exec_target = $(manifests)

clean-extra += clean-tmp

level = ../../
include ../../Makefile

clean-tmp:
	rm -f curl.manifest.sgx
