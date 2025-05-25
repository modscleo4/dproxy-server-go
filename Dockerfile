# Build the application from source
FROM golang:1.24 AS build

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN GOOS=linux go build -o /app/dproxy-server

# Deploy the application binary into a lean image
FROM alpine:latest AS runtime

WORKDIR /app

VOLUME /app/keys

EXPOSE 8080

COPY --from=build /app/dproxy-server /bin/dproxy-server

RUN addgroup -S user && adduser -S user -G user

USER user

ENTRYPOINT ["/bin/dproxy-server"]
