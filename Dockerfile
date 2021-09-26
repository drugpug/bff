FROM golang:1.17-alpine AS build
WORKDIR /app
COPY . .
RUN go mod download
RUN go build -o ./bff

FROM alpine:3.13
WORKDIR /
COPY --from=build /app/bff /bff
COPY --from=build /app/*.pem .
EXPOSE 3000
ENTRYPOINT ["/bff"]