# Minify client side assets (JavaScript)
FROM node:latest AS build-js

RUN npm install gulp gulp-cli -g

WORKDIR /build
COPY . .
RUN npm install --only=dev
RUN gulp


# Build Golang binary
FROM golang:1.21 AS build-golang

WORKDIR /go/src/github.com/gophish/gophish
COPY . .
RUN go get -v && go build -v

# Build goose binary
ENV TMPDIR=/tmp
RUN mkdir -p $TMPDIR && chmod 777 $TMPDIR
RUN go install github.com/pressly/goose/v3/cmd/goose@v3.14.0
RUN cp /go/bin/goose /go/src/github.com/gophish/gophish/


# Runtime container
FROM debian:stable-slim

RUN useradd -m -d /opt/gophish -s /bin/bash app

RUN apt-get update && \
	apt-get install --no-install-recommends -y \
	jq \
	libcap2-bin \
	ca-certificates \
	curl \
	sqlite3 \
	&& apt-get clean && \
	rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /opt/gophish
COPY --from=build-golang /go/src/github.com/gophish/gophish/ ./
COPY --from=build-js /build/static/js/dist/ ./static/js/dist/
COPY --from=build-js /build/static/css/dist/ ./static/css/dist/
COPY --from=build-golang /go/src/github.com/gophish/gophish/config.json ./
RUN chown app. config.json

# Copy goose binary to a PATH location
COPY --from=build-golang /go/src/github.com/gophish/gophish/goose /usr/local/bin/
RUN chmod +x /usr/local/bin/goose

RUN setcap 'cap_net_bind_service=+ep' /opt/gophish/gophish

USER app
RUN sed -i 's/127.0.0.1/0.0.0.0/g' config.json
RUN touch config.json.tmp

EXPOSE 3333 8080 8443 80

CMD ["./docker/run.sh"]
