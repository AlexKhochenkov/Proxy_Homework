FROM golang:latest

WORKDIR /go/src/app

COPY .. .

RUN go build -o main ./cmd

EXPOSE 8000

CMD ["./main"]