sourcedir := "./src"
builddir := "./build/bin"
CFLAGS := "-Wall -std=c++23"
LIBS := "-lssl -lcrypto"

build-all: build-client build-server

build-client:
  c++ {{CFLAGS}} -o {{builddir}}/client {{LIBS}} {{sourcedir}}/client.cpp

build-server:
  c++ {{CFLAGS}} -o {{builddir}}/server {{LIBS}} {{sourcedir}}/server.cpp

run-client: build-client
  {{builddir}}/client

run-server: build-server
  {{builddir}}/server

create-openssl:
  openssl req -x509 -newkey rsa:4096 -keyout cert/key.pem -out cert/cert.pem -sha256 -days 365
