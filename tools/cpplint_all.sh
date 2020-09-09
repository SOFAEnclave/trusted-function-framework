#!/usr/bin/env bash

TOPDIR="$(readlink -f $(dirname $0)/..)"
[ -n "$1" ] && DIRS="$@" || DIRS="."
CPPLINT=$(dirname $0)/cpplint.py

if [ -z "$DIRS" ] ; then
    echo "Usage $0 dir1 [dir2 [...]]"
    exit 1
fi

ret=0
for item in $DIRS ; do
    if [ -f "$item" ] ; then
        echo "----[CPPLINT] $item"
        $CPPLINT $item
        exit $?
    elif [ -d "$item" ] ; then
        echo "Do cpplint check in directory $item"
        for f in  $(find $item -type f -iname "*.h" -o -iname "*.cpp") ; do
            echo $f | grep -q ".*\.pb\.[cc|h]" && continue
            echo $f | grep -q ".*\.grpc\.pb\.[cc|h]" && continue
            echo $f | grep -q "third_party\/" && continue
            echo $f | grep -q "build\/" && continue
            echo "----[CPPLINT] $f"
            $CPPLINT $f | grep -o '^${f}:.*$' && ret=1
        done
    else
        echo "Usage: $0 <directory>"
        exit 1
    fi
done

exit $ret
