FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -o /bin/service ./main.go

FROM scratch
COPY --from=build /bin/service /bin/service
CMD ["/bin/service"]
