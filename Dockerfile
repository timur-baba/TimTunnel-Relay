FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/timtunnel-relay .

FROM alpine:3.20
RUN adduser -D -H -s /sbin/nologin timtunnel
COPY --from=build /out/timtunnel-relay /usr/local/bin/timtunnel-relay
USER timtunnel
ENTRYPOINT ["/usr/local/bin/timtunnel-relay"]
