obj-m += dm-security.o region-mapper.o

# CFLAGS += "-g -DDEBUG"
# ccflags-y += ${CFLAGS}
# CC += ${CFLAGS}

KDIR = /lib/modules/$(shell uname -r)/build

all:
	make -C $(KDIR) M=$(PWD) modules
debug:
	make -C $(KDIR) M=$(PWD) modules EXTRA_CFLAGS="-g -DDEBUG"
clean:
	make -C $(KDIR) M=$(PWD) clean
install: debug
	insmod region-mapper.ko
	insmod dm-security.ko
	./setup_security_device.sh /dev/vdc
uninstall:
	./remove_security_device.sh
	rmmod dm_security
	rmmod region_mapper
gdb:
	@cat /sys/module/dm_security/sections/.text