IMAGE_NAME := arunsworld/flexi-ssh
LD_FLAGS := -s -w
TARGETS := .

.PHONY: build
build: pack-build

.PHONY: pack-build
pack-build:
	pack build ${IMAGE_NAME}:latest \
		--env "BP_GO_TARGETS=${TARGETS}" \
		--env "BP_GO_BUILD_LDFLAGS=${LD_FLAGS}" \
		--builder paketobuildpacks/builder:base