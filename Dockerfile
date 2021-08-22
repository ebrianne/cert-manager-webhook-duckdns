FROM golang:1.15-alpine3.12 AS build_deps

RUN apk add --no-cache git

WORKDIR /workspace
ENV GO111MODULE=on
ENV GOPATH="/workspace/.go"

COPY go.mod .
COPY go.sum .

RUN go mod download

FROM build_deps AS build

COPY . .

RUN CGO_ENABLED=0 go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM alpine:latest

RUN apk add --no-cache ca-certificates

COPY --from=build /workspace/webhook /usr/local/bin/webhook

ENTRYPOINT ["webhook"]