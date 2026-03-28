BINARY := podsentry

.PHONY: build test cover fmt vet tidy clean run

build:
	go build -o $(BINARY) ./main.go

test:
	go test ./... -cover

cover:
	go test ./... -coverprofile=coverage.out
	go tool cover -func=coverage.out

fmt:
	gofmt -w .

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -f $(BINARY) coverage.out

run: build
	./$(BINARY) --help
