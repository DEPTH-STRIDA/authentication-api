# Latest golang image on alpine linux
FROM golang:1.22.0 as builder

# Env variables
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

# Set environment variables for the build stage
ENV PORT=8000
ENV HOST=localhost
ENV LOGGER=2 
ENV DB_HOST=localhost
ENV DB_PORT=5432
ENV DB_NAME=crypto_database
ENV DB_USER=crypto_user
ENV DB_PASS=228
ENV DB_TYPE=postgres
ENV TOKEN_PASSWORD=98h62wNoyBVlZTBsqtBW9tC11QeGIzkIyEGzRR2chXSTqo7OiFcRrjx6gJkkADHp
ENV HASH_PASSWORD=wXRuiFOyCHQIB58DrBBIe2QHjbwkmSCivBP4puZqYZId-t9131g7sJbJCc4HUg73 
ENV SMTP_MAIL=awesome.gail@yandex.ru
ENV SMTP_PASSWORD=nnczofiwvuivooil
ENV SMTP_HOST=smtp.yandex.ru
ENV SMTP_PORT=465
ENV SMTP_PORT_WITHOUT_ENCRYPTION=587

# Work directory
WORKDIR /docker-go

# Installing dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copying all the files
COPY main.go ./
COPY utils/ ./utils/
COPY smtp/ ./smtp/
COPY request/ ./request/
COPY models/ ./models/
COPY logger/ ./logger/
COPY handler/ ./handler/

# Building the application
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o authentication-api

# Fetching the latest alpine image
FROM alpine:3.16 as production

# Certificates
RUN apk add --no-cache ca-certificates

# Copying built assets from builder
COPY --from=builder /docker-go/authentication-api .

# Copy environment variables from builder
ENV PORT=${PORT}
ENV HOST=${HOST}
ENV LOGGER=${LOGGER}
ENV DB_HOST=${DB_HOST}
ENV DB_PORT=${DB_PORT}
ENV DB_NAME=${DB_NAME}
ENV DB_USER=${DB_USER}
ENV DB_PASS=${DB_PASS}
ENV DB_TYPE=${DB_TYPE}
ENV TOKEN_PASSWORD=${TOKEN_PASSWORD}
ENV HASH_PASSWORD=${HASH_PASSWORD}
ENV SMTP_MAIL=${SMTP_MAIL}
ENV SMTP_PASSWORD=${SMTP_PASSWORD}
ENV SMTP_HOST=${SMTP_HOST}
ENV SMTP_PORT=${SMTP_PORT}
ENV SMTP_PORT_WITHOUT_ENCRYPTION=${SMTP_PORT_WITHOUT_ENCRYPTION}

# Starting our application
CMD ["./authentication-api"]

# Exposing server port
EXPOSE 5421
EXPOSE 8001