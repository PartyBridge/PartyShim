FROM golang:1.19-buster AS builder
WORKDIR /project
COPY . ./
RUN cd /project/cmd/partyshim && go build -ldflags -o /project/bin/partyshim

FROM registry.access.redhat.com/ubi8/ubi-minimal
EXPOSE 8080
COPY --from=builder /project/bin/partyshim /partyshim

ENTRYPOINT ["/partyshim"]
