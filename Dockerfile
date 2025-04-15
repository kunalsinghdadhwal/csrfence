FROM golang:alpine AS builder

RUN mkdir /build
ADD . /build

WORKDIR /build
RUN go build -o main .

# stage 2

FROM alpine:latest

RUN adduser -S -D -H -h /app appuser
USER appuser

COPY . /app
COPY --from=builder /build/main /app/

RUN chown 

WORKDIR /app
EXPOSE 42069 
CMD ["./main"]
