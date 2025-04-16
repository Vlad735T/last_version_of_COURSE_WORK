FROM golang:1.22
WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY SERVER.go ./
COPY settings.env ./
COPY AllPages/ ./AllPages/

CMD ["sh", "-c", "set -a && . ./settings.env && go run SERVER.go"]