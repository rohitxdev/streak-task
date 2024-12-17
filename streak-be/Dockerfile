# syntax=docker/dockerfile:1
ARG BASE_IMAGE_TAG


# Development image
FROM golang${BASE_IMAGE_TAG} AS development

WORKDIR /app

RUN apk add --no-cache build-base bash git

RUN go install github.com/air-verse/air@latest

COPY go.mod go.sum ./

RUN go mod download -x

ENTRYPOINT ["./run", "watch"]


# Production builder image
FROM development AS production-builder

COPY . .

RUN ./run build


# Final production image
FROM scratch AS production

COPY --from=production-builder /app/.local/bin .

ENTRYPOINT ["./main"]
