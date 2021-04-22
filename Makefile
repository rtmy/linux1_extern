obj-m += module_final.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
test:
	-sudo rmmod module_final
	sudo dmesg -C
	sudo insmod module_final.ko
	dmesg
