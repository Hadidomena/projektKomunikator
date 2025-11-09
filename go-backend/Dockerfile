# Use the official Go image.
FROM golang:1.25.3-alpine

# Set the working directory inside the container.
WORKDIR /app

# Install air for live reloading.
RUN go install github.com/air-verse/air@latest

# Copy go.mod and go.sum files to download dependencies first.
# This leverages Docker's layer caching.
COPY go.mod go.sum ./
RUN go mod download

# Copy the .air.toml configuration file
COPY .air.toml ./

# The command to run the application will be provided by docker-compose.
CMD ["air", "-c", ".air.toml"]
