# Use the official Go image.
FROM golang:1.25.3-alpine

WORKDIR /app
RUN go install github.com/air-verse/air@latest
COPY go.mod go.sum ./
RUN go mod download

COPY .air.toml ./
CMD ["air", "-c", ".air.toml"]
