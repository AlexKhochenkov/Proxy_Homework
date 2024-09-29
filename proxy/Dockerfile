FROM golang:latest

WORKDIR /go/src/app

COPY .. .

RUN go build -o main ./proxy

EXPOSE 8080

CMD ["./main"]