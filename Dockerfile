FROM golang:1.24-alpine AS build

RUN apk add --no-cache gcc g++

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 go build -o /app/dproxy-server

FROM alpine:latest

WORKDIR /app

VOLUME /app/db
VOLUME /app/keys

EXPOSE 8080
EXPOSE 1080
EXPOSE 8081

RUN addgroup -S user && adduser -S user -G user

USER user

COPY --from=build /app/dproxy-server /bin/

ENTRYPOINT ["/bin/dproxy-server"]
