.PHONY: test
test:
	@go test -v -race ./...

.PHONY: build
build:
	@go build -o bin/main cmd/main.go

.PHONY: run
run: build
	@./bin/main

.PHONY: clean
clean:
	@rm -f bin/main

