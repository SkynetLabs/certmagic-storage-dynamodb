# envVars defines all the environment variables the project depends on. These
# are typically provided by docker-compose files or .env files.
envVars= \
	SKYDB_ENTROPY=lJAuxnufpy7BbNCbVUKWShIinDBipdnd1hr/d/ZqHLI= \
	SKYDB_ENDPOINT=localhost:9980

deps:
	go get ./...

fmt:
	gofmt -s -l -w .

vet:
	go vet .

test: deps fmt vet
	$(envVars) go test -v -coverprofile=cover.out .
