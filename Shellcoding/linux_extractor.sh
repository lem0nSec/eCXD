#!/bin/bash

if [ -z "$0" ]
then
        echo "usage: $0 /path/to/executable"
        exit
fi

/usr/bin/objdump -d $1 \
        | grep '[0-9a-f]:' \
        | grep -v 'file' \
        | cut -f2 -d: \
        | cut -f1-6 -d' ' \
        | tr -s ' ' \
        | tr '\t' ' ' \
        | sed 's/ $//g' \
        | sed 's/ /\\x/g' \
        | paste -d '' -s \
        | sed 's/^/"/' \
        | sed 's/$/"/g'
