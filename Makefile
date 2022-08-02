obj-m += dm-security.o io-aware.o hot-cold-region.o

KDIR = /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
install: all
	insmod io-aware.ko
	insmod hot-cold-region.ko
	insmod dm-security.ko
	./setup_security_device.sh /dev/vdc
uninstall:
	./remove_security_device.sh
	rmmod dm_security
	rmmod hot_cold_region
	rmmod io_aware