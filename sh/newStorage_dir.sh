#!/usr/bin/env sh
#
# newStorage_dir.sh
# Copyright © 2014 tox <tox@rootkit>
#

datadir=$1
public=$2

mkdir -- "$datadir/$public"
