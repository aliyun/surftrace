obj-m += sys_high.o

ifneq ($(KERNELVER),)
	KERNELDIR := /usr/src/kernels/$(KERNELVER)
endif

ifeq ($(KERNELDIR),)
	KERNELDIR := /lib/modules/$(shell uname -r)/build
endif
PWD := $(shell pwd)
all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.ko *.mod* *.o modules.* Module.symvers

install:
	insmod sys_high.ko

remove:
	rmmod sys_high