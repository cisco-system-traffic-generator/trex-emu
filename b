#! /usr/bin/env bash
export  GOPATH=`pwd`
export PKG_CONFIG_PATH=`pwd`/external_share/zmq/x86_64/
export CGO_CFLAGS="-g -O2 -I"`pwd`/external_share/zmq/x86_64/include
export CGO_LDFLAGS="-g -O2 -L"`pwd`/external_share/zmq/x86_64/
export GOBIN=`pwd`/bin


