obj-m := dict.o
obj-m += nft_dict.o
KERNEL_VERSION := $(shell uname -r)
IDIR := /lib/modules/$(KERNEL_VERSION)/kernel/net/netfilter/
KDIR := /lib/modules/$(KERNEL_VERSION)/build
PWD := $(shell pwd)
default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules

install:
	install -v -m 644 dict.ko $(IDIR)
	install -v -m 644 nft_dict.ko $(IDIR)
	depmod "$(KERNEL_VERSION)"
	[ "$(KERNEL_VERSION)" != `uname -r` ] || modprobe dict.ko nft_dict.ko

clean:
	rm -rf Module.markers modules.order Module.symvers
	rm -rf dict.ko dict.mod.c dict.mod.o dict.o
	rm -rf nft_dict.ko nft_dict.mod.c nft_dict.mod.o nft_dict.o
