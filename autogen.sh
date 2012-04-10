#!/bin/sh

gnulib-tool --quiet --import \
    getpass \
    strndup \
    byteswap \
    stdint \
    stdbool \
    xvasprintf || exit 1

autoreconf -f -i || exit 1

if test x$NOCONFIGURE = x; then
    exec ./configure "$@"
fi

