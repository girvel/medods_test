FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod go.sum main.go ./
RUN CGO_ENABLED=0 go build -o /bin/service ./main.go

FROM alpine
COPY --from=build /bin/service /bin/service
CMD ["/bin/service"]
