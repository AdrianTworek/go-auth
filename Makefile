MIGRATIONS_PATH = ./cmd/migrate/migrations

.PHONY: migrate-create
migration:
	@migrate create -seq -ext sql -dir $(MIGRATIONS_PATH) $(filter-out $@,$(MAKECMDGOALS))

.PHONY: migrate-up
migrate-up:
	@migrate -database postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable -path $(MIGRATIONS_PATH) up


.PHONY: migrate-down
migrate-down:
	@migrate -database postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable -path $(MIGRATIONS_PATH) down

.PHONY: tools
tools:
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

.PHONY: fmt
fmt:
	@golangci-lint fmt ./...

.PHONY: vet
vet:
	@go vet ./...

.PHONY: lint
lint:
	@golangci-lint run ./...

.PHONY: lint-fix
lint-fix:
	@golangci-lint run --fix ./...

.PHONY: check
check: fmt vet lint test

.PHONY: test
test:
	@go test -count=1 -v ./...

.PHONY: build
build:
	@go build -o bin/main cmd/main.go

.PHONY: run
run: build
	@./bin/main

.PHONY: clean
clean:
	@rm -f bin/main
