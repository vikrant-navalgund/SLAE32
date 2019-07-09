#! /bin/sh

SOURCE_FILE=$1
PORT_NUMBER=$2

sed -i "s/\(PORT_BIND \)\(.*\)/\1${PORT_NUMBER}/" ${SOURCE_FILE}
nasm -f bin ${SOURCE_FILE} -o ${SOURCE_FILE%.*}.bin

