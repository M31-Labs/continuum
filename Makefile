VERSION ?= dev
DIST_DIR ?= dist

.PHONY: test fmt vet race audit-schema-artifact

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
