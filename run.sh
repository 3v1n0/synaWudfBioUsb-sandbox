#!/bin/sh
set -ex

DEVICE=$(lsusb | grep 'VeriMark' | awk -F '[^0-9]+' '{ print "/dev/bus/usb/" $2 "/" $3 }')
PWD=$(pwd)
BASENAME=$(basename "$PWD")
#XPFWEXT=$(ls ./*.xpfwext)
NOW=$(date +%s)

SCRIPT="${NOW}-usb.txt"
PLAYBACK=

while getopts "p:" arg; do
    case $arg in
        p) 
            SCRIPT=$OPTARG
            PLAYBACK=1
            ;;
        *)
            echo "Usage: $0 [-p usb-script.txt] <nop|enroll|identify>"
            exit 0
            ;;
    esac
done
shift $((OPTIND-1))

WHAT=$1

docker run --rm -it \
    --device $DEVICE \
    --env-file .env \
    -w /$BASENAME \
    -e USB_SCRIPT=$SCRIPT \
    -e USB_PLAYBACK=$PLAYBACK \
    -v $PWD:/$BASENAME \
    -v $PWD/usb.txt:/root/.wine/drive_c/usb.txt \
    wine:validity sh -c "wine64 b.exe $WHAT 2> ${NOW}-wine.log" | tee "${NOW}.log"

    #-v $PWD/$XPFWEXT:/root/.wine/drive_c/windows/system32/$XPFWEXT \
