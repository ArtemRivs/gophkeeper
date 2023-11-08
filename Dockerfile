FROM golang:1.21

RUN apt-get update && apt-get install -y \
bash \
git \
make \
&& rm -rf /var/lib/atp/lists/*

WORKDIR /usr/local/src
COPY ["go.mod", "go.sum", "./"]
RUN go mod download

COPY ./ ./
RUN go build -o ./bin/gophkeeper-srv cmd/server/main.go

CMD ["./bin/gophkeeper-srv"]