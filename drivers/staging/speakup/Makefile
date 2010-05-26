KERNELDIR = /lib/modules/`uname -r`/build

all: modules

modules:
	make -C $(KERNELDIR) M=`pwd` `cat allmodule.mk` 

modules_install:
	make INSTALL_MOD_DIR=speakup -C $(KERNELDIR) M=`pwd` `cat allmodule.mk` $@

clean:
	make -C $(KERNELDIR) M=`pwd` `cat allmodule.mk` $@
