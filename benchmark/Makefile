obj-m += chainmode.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

test: all
	@insmod chainmode.ko
	@dmesg -t | tail -n 51 | split -l 17 && \
		mv xaa chainmodebench-encrypt.csv && \
		mv xab chainmodebench-decrypt.csv && \
		mv xac chainmodebench-encrypt-decrypt.csv
	@rmmod chainmode.ko
