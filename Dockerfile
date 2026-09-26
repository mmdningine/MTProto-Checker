FROM golang:1.26 AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o main cmd/mtproto-checker/main.go

# Stage 2: Run the Go app in a minimal image
FROM alpine:3.24

RUN apk add --no-cache curl

WORKDIR /app

COPY --from=builder /app/main .

CMD ["./main"]
