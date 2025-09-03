sourcedir := "./src"
builddir := "./build/bin"
CFLAGS := "-Wall -std=c++23"

build-all: build-client build-server

build-client:
  c++ {{CFLAGS}} -o {{builddir}}/client {{sourcedir}}/client.cpp

build-server:
  c++ {{CFLAGS}} -o {{builddir}}/server {{sourcedir}}/server.cpp

run-client: build-client
  {{builddir}}/client

run-server: build-server
  {{builddir}}/server
