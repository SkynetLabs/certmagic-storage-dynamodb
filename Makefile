# envVars defines all the environment variables the project depends on. These
# are typically provided by docker-compose files or .env files.
envVars= \
	CADDY_SKYDB_ENTROPY=94902ec67b9fa72ec16cd09b5542964a12229c3062a5d9ddd61aff77f66a1cb2 \
	CADDY_SKYDB_ENDPOINT=localhost:9980

deps:
	go get ./...

fmt:
	gofmt -s -l -w .

vet:
	go vet .

test: deps fmt vet
	$(envVars) go test -v -coverprofile=cover.out .
