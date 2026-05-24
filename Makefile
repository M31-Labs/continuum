VERSION ?= dev
DIST_DIR ?= dist
IMAGE ?= continuum:dev
COMMIT ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

.PHONY: test fmt vet race audit-schema-artifact release-artifacts container-image

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

vet:
	go vet ./...

race:
	go test -race ./...

audit-schema-artifact:
	VERSION="$(VERSION)" DIST_DIR="$(DIST_DIR)" bash scripts/build-audit-schema-artifact.sh

release-artifacts:
	VERSION="$(VERSION)" DIST_DIR="$(DIST_DIR)" COMMIT="$(COMMIT)" BUILD_DATE="$(BUILD_DATE)" bash scripts/build-release-artifacts.sh

container-image:
	docker build \
		--build-arg VERSION="$(VERSION)" \
		--build-arg COMMIT="$(COMMIT)" \
		--build-arg BUILD_DATE="$(BUILD_DATE)" \
		-t "$(IMAGE)" \
		.
