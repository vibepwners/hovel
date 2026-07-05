KDIR ?= /lib/modules/$(shell uname -r)/build

obj-m += kshell.o
obj-m += kshell_nacl.o
obj-m += pic_hook.o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean
