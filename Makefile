
all: build push

docker-build-release:
	@if [ -z "$(tag)" ]; then \
		echo "Error: tag is required. Usage: make build-all tag=<tag>"; \
		exit 1; \
	fi
	docker buildx build --platform linux/arm64,linux/amd64 -t fosrl/client:latest -f Dockerfile --push .
	docker buildx build --platform linux/arm64,linux/amd64 -t fosrl/client:$(tag) -f Dockerfile --push .

build:
	docker build -t fosrl/client:latest .

push:
	docker push fosrl/client:latest

test:
	docker run fosrl/client:latest

local: 
	CGO_ENABLED=0 go build -o client

go-build-release:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/client_linux_arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/client_linux_amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/client_darwin_arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/client_darwin_amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/client_windows_amd64.exe
	CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -o bin/client_freebsd_amd64
	CGO_ENABLED=0 GOOS=freebsd GOARCH=arm64 go build -o bin/client_freebsd_arm64

clean:
	rm client
