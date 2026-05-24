.PHONY: test fmt vet race

test:
	go test ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './.git/*')

vet:
	go vet ./...

race:
	go test -race ./...
