FROM golang:alpine AS builder
WORKDIR /build
ADD go.mod .
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/canal-controller cmd/main.go

FROM alpine:3.11.6
WORKDIR /build
COPY --from=builder /build/bin/canal-controller /canal-controller
CMD /canal-controller --logtostderr=true