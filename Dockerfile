FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git

WORKDIR /app

# --- Layer 1: cache Go module downloads ---
COPY go.mod go.sum* ./
RUN go mod download

# --- Layer 2: cache templ CLI binary ---
RUN go install github.com/a-h/templ/cmd/templ@v0.3.977

# --- Layer 3: copy source and build ---
COPY . .
RUN templ generate && \
    go mod tidy && \
    CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/server

FROM alpine:3.20

RUN apk --no-cache add ca-certificates

COPY --from=builder /server /server

EXPOSE 8080

ENTRYPOINT ["/server"]
