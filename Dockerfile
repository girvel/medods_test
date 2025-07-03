FROM golang:1.24 AS build
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
COPY src ./src
RUN CGO_ENABLED=0 go build -o /bin/service .

FROM scratch
COPY --from=build /bin/service /bin/service
CMD ["/bin/service"]
