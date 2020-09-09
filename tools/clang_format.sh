#!/usr/bin/env bash

CLANG_WHITE_LIST_FILE=".clang-dirs"

do_file_format() {
    echo "[FORMAT] $1"
    clang-format -style=file -i $1
}

do_dir_format() {
    local dir="$1"
    local sub_dirs=""

    #echo "-------- $dir --------"
    if [ -e "$dir/$CLANG_WHITE_LIST_FILE" ] ; then
        sub_dirs="$(cat $dir/$CLANG_WHITE_LIST_FILE | xargs)"
        for d in $sub_dirs ; do
            do_dir_format $dir/$d;
        done
    else
        for f in $(find $dir -iname "*.cpp" -o -iname "*.cc" -o -iname "*.h") ; do
            # Anyway, we always ignore these two directories
            echo $f | grep -q "third_party\/" && continue
            echo $f | grep -q "build\/" && continue
            do_file_format $f
        done
    fi
}

# Show the help menu
if [ "$1" == "-h" -o "$1" == "--help" ] ; then
    echo "Usage: $0 [file-or-directory[, file-or-directory[, ...]]]"
    exit 0
fi

# Get the list of files or directories to be formatted
if [ -n "$1" ] ; then
    FORMATITEMS="$@"
elif [ -e "$CLANG_WHITE_LIST_FILE" ] ; then
    FORMATITEMS="$(cat $CLANG_WHITE_LIST_FILE | xargs)"
else
    FORMATITEMS="."
fi

# Fromat all files and directories
for item in $FORMATITEMS ; do
    if [ -f "$item" ] ; then
        if echo "$item" | grep -q -E ".*\.cpp|.*\.cc|.*\.h" ; then
            do_file_format $item
        else
            echo "[IGNORE] Invalid C++ source or header file: $item"
        fi
    elif [ -d "$item" ] ; then
       do_dir_format $item
    else
        echo "[IGNORE] Invalid file or directory: $item"
    fi
done
