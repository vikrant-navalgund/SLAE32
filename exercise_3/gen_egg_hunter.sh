#! /bin/sh

# Utility script written by - Vikrant Navalgund

SOURCE_FILE=$1
EGG_TAG=$2

echo "\n[+] Generating egg hunter shellcode for egg tag: \"$EGG_TAG\" \n"
_EGG_TAG="0x"$(printf $(echo $EGG_TAG | tr -d '\\x') | tac -rs ..)
sed -i "s/\(_EGG_TAG \)\(.*\)/\1${_EGG_TAG}/" ${SOURCE_FILE}
nasm -f bin ${SOURCE_FILE} -o ${SOURCE_FILE%.*}.bin

