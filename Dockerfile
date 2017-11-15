FROM golang:1.9-alpine as builder

ENV PKG=/go/src/github.com/skuid/keyman
ADD . $PKG
WORKDIR $PKG

RUN go install -ldflags '-w'

FROM alpine:3.6

RUN apk add -U ca-certificates

COPY --from=builder /go/bin/keyman /bin/keyman

ENTRYPOINT ["/bin/keyman"]
