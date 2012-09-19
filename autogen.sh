#!/bin/sh

srcdir=$(dirname $0)
test -z "$srcdir" && srcdir=.

cwd=$(pwd)
cd "$srcdir"

autoreconf -vfi || exit 1

cd "$cwd"
$srcdir/configure $@
