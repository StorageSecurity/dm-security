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
test: install
	dd if=/dev/zero of=/dev/mapper/security1 bs=512 count=1
	cat /proc/region-mapper/252:32/0
	echo "11" > /proc/region-mapper/252:32/0
	cat /proc/region-mapper/252:32/0
	dd if=/dev/mapper/security1 of=security1.txt bs=512 count=1