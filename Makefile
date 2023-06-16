MODULE_NAME := my_http_sniffer


obj-m := $(MODULE_NAME).o
$(MODULE_NAME)-objs := http_sniffer.o hashmap.o
MY_CFLAGS += -g -DDEBUG
ccflags-y += ${MY_CFLAGS}
CC += ${MY_CFLAGS}

map_func: map_func.c self_define.h
	gcc map_func.c -o map_func
user_space: user_space.c self_define.h
	gcc user_space.c -o user_space
kernel_module:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
kernel_module_debug:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	EXTRA_CFLAGS="$(MY_CFLAGS)"
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
