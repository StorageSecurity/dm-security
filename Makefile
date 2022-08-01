obj-m += dm-security.o io-aware.o

KDIR = /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean
install:
	insmod io-aware.ko
	insmod dm-security.ko
	./setup_security_device.sh /dev/vdc
uninstall:
	./remove_security_device.sh
	rmmod dm_security
	rmmod io_aware