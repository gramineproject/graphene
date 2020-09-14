# This makefile should be used to generate Dockerfiles for all prebuilt images. Prebuilt images are
# located in images/*. These files are then pulled by Dockerhub to generate the public Dockerhub
# images of Graphene. When GSC changes substentially in its initial Graphene build (e.g. when
# template/Dockerfile.*.compile.template changes), these automatically generated files need to be
# updated. Genrally, changes to Graphene do not require to rebuild these Docker files.

IMAGES=graphene_aks
VERSIONS=latest

all: $(addsuffix .dockerfile, $(addprefix $(addprefix images/, ${IMAGES}), .${VERSIONS}))

config.aks.%.yaml:
	printf "Distro: \"ubuntu18.04\"\nGraphene:\n    Repository:\
	 \"https://github.com/oscarlab/graphene.git\"\n    Branch: \"$*\"\nSGXDriver:\n    \
	 Repository: \"https://github.com/intel/SGXDataCenterAttestationPrimitives.git\"\n \
	    Branch: \"LD_1.22 && cp -r driver/linux/* .\"\n" > $@

images/graphene_aks.latest.dockerfile: config.aks.master.yaml
	./gsc build-graphene -f -c $< graphene-aks
	mv graphene-aks/Dockerfile.compile $@
	rm -r graphene-aks

distclean: clean
	$(RM) images/*

clean:
	$(RM) config.aks.*.yaml
