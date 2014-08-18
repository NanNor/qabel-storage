#!/usr/bin/env sh
#
# rmStorage_dir.sh
# Copyright © 2014 tox <tox@rootkit>
#

datadir=$1
public=$2

rm -r -- "$datadir/$public"
