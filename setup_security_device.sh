#!/bin/sh

dmsetup create security1 --table "0 `blockdev --getsz $1` security babebabebabebabebabebabebabebabebabebabebabebabebabebabebabebabe 0 $1 0 0"
# mkfs.xfs -f /dev/mapper/security1
# mount /dev/mapper/security1 mnt
