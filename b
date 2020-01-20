#! /usr/bin/env bash
export  GOPATH=`pwd`
export PKG_CONFIG_PATH=`pwd`/external_share/zmq/x86_64/
export CGO_CFLAGS="-g -O2 -I"`pwd`/external_share/zmq/x86_64/include
export CGO_LDFLAGS="-g -O2 -L"`pwd`/external_share/zmq/x86_64/
export GOBIN=`pwd`/bin

if [[ -f $PKG_CONFIG_PATH/libzmq.so && ! -f $PKG_CONFIG_PATH/libzmq.so.5 ]]; then
    ln -s $PKG_CONFIG_PATH/libzmq.so $PKG_CONFIG_PATH/libzmq.so.5
fi
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$PKG_CONFIG_PATH
