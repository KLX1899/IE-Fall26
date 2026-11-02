FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -o /proxy .

FROM scratch
COPY --from=build /proxy /proxy
USER 65532:65532
ENTRYPOINT ["/proxy"]
