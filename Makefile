.PHONY: fmt lint test build run

lint:
	GOBIN=$(PWD)/build/bin go run ./build/lint.go

fmt:
	go mod tidy
	goimports -w .
	gofumpt -l -w .

build:
	docker build -t my-dev-container --platform linux/amd64 .

run: build
	docker run -it --rm -v "$(PWD):/workspace" -w /workspace my-dev-container

test:
	./run_test
