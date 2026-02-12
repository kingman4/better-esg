FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod ./
COPY go.sum* ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/server

FROM alpine:3.20

RUN apk --no-cache add ca-certificates

COPY --from=builder /server /server

EXPOSE 8080

ENTRYPOINT ["/server"]
