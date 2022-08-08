#!/usr/bin/python
#
# This is a Hello World example that formats output as fields.

import sys

from bcc import BPF

def callback(ctx, data, size):
    event = b['bio_account_ring'].event(data)
    print("%20ld %5d %5d %5s %10d %10d" % 
        (event.ts, event.major, event.minor, 'W' if event.rw_mode == 1 else 'R', event.start, event.length))

major = 253
minor = 0

# load BPF program
b = BPF(src_file="submit_bio.c", cflags=["-DDEV_MAJOR=%d" % major, "-DDEV_MINOR=%d" % minor])
b.attach_kprobe(event="__submit_bio", fn_name="bio_account_fn")
b.attach_kretprobe(event="table_load", fn_name="table_load_ret_fn")

b["bio_account_ring"].open_ring_buffer(callback)

# header
print("%20s %5s %5s %5s %10s %10s" % ("TIME(ns)", "MAJOR", "MINOR", "RW", "SRART", "LENGTH"))

# format output
try:
    while 1:
        b.ring_buffer_consume()
        # time.sleep(0.5)
except KeyboardInterrupt:
    sys.exit()
