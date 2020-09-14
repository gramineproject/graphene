# This makefile should be used to generate Dockerfiles for all prebuilt images. Prebuilt images are
# located in images/*. These files are then pulled by Dockerhub to generate the public Dockerhub
# images of Graphene. When GSC changes substantially in its initial Graphene build (e.g. when
# template/Dockerfile.*.compile.template changes), these automatically generated files need to be
# updated. Generally, changes to Graphene do not require rebuilding these Docker files.

IMAGES=graphene_aks
VERSIONS=latest

all: $(addsuffix .dockerfile, $(addprefix $(addprefix images/, ${IMAGES}), .${VERSIONS}))

config.aks.%.yaml:
	printf \
	"Distro: \"ubuntu18.04\"\n\
	Graphene:\n\
	    Repository: \"https://github.com/oscarlab/graphene.git\"\n\
	    Branch: \"$*\"\n\
	SGXDriver:\n\
	    Repository: \"https://github.com/intel/SGXDataCenterAttestationPrimitives.git\"\n\
	    Branch: \"DCAP_1.7 && cp -r driver/linux/* .\"\n" > $@

images/graphene_aks.latest.dockerfile: config.aks.master.yaml
	./gsc build-graphene -f -c $< graphene-aks
	mv graphene-aks/Dockerfile.compile $@
	$(RM) -r graphene-aks

.PHONY: distclean
distclean: clean
	$(RM) images/*

.PHONY: clean
clean:
	$(RM) config.aks.*.yaml
