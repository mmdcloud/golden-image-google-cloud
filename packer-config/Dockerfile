FROM alpine:3.14 AS build

COPY ../packer_1.11.1_linux_amd64.zip .

RUN /usr/bin/unzip packer_1.11.1_linux_amd64.zip

FROM gcr.io/google.com/cloudsdktool/cloud-sdk:alpine
RUN apk update && apk upgrade && \
    apk --no-cache add ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build packer /usr/bin/packer
ENTRYPOINT ["/usr/bin/packer"]