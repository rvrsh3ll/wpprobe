FROM golang:1.23-alpine

RUN go install github.com/Chocapikk/wpprobe@latest

ENTRYPOINT ["/go/bin/wpprobe"]