#!/usr/bin/env sh
#
# rmStorage_blob.sh
#

datadir=$1
public=$2
blob=$3

rm -- "$datadir/$public/$blob"
