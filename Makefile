release:
	goreleaser release --snapshot --clean
build:
	go build -o ./ciscollector ./cmd/ciscollector
run: 
	go build -o ./ciscollector ./cmd/ciscollector && ./ciscollector
