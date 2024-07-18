FROM alpine:3.14 AS build

ARG PACKER_VERSION
ARG PACKER_VERSION_SHA256SUM

COPY packer_${PACKER_VERSION}_linux_amd64.zip .
RUN echo "${PACKER_VERSION_SHA256SUM}  packer_${PACKER_VERSION}_linux_amd64.zip" > checksum && sha256sum -c checksum

RUN /usr/bin/unzip packer_${PACKER_VERSION}_linux_amd64.zip

FROM gcr.io/google.com/cloudsdktool/cloud-sdk:alpine
RUN apk update && apk upgrade && \
    apk --no-cache add ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build packer /usr/bin/packer
ENTRYPOINT ["/usr/bin/packer"]