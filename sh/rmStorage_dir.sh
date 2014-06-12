#!/usr/bin/env sh
#
# rmStorage_dir.sh
# Copyright © 2014 tox <tox@rootkit>
#

public=$1
datadir=$2

rm -r -- "$public/$datadir"
