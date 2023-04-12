release:
	goreleaser release --snapshot --clean
build:
	go build -o ./ciscollector ./cmd/ciscollector
run: 
	go build -o ./ciscollector ./cmd/ciscollector && ./ciscollector -r
linux: 
	GOOS=linux GOARCH=amd64 go build -o ./linux/ciscollector ./cmd/ciscollector