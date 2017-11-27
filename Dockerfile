FROM golang:1.9-alpine as builder

ENV PKG=/go/src/github.com/skuid/keyman
ADD . $PKG
WORKDIR $PKG

ARG COMMIT_SHA

RUN go install -ldflags "-w -X github.com/skuid/keyman/vendor/github.com/skuid/spec/metrics.commit=${COMMIT_SHA}"

FROM alpine:3.6

RUN apk add -U ca-certificates

COPY --from=builder /go/bin/keyman /bin/keyman

ENTRYPOINT ["/bin/keyman"]
CMD ["server"]
