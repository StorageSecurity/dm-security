#!/bin/sh

dmsetup create security1 --table "0 `blockdev --getsz $1` security aes-cbc-essiv:sha256 babebabebabebabebabebabebabebabe 0 $1 0"
mkfs.xfs -f /dev/mapper/security1
mount /dev/mapper/security1 mnt
