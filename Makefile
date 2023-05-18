obj-m := http_sniffer.o


all: kernel_module user_space

map_test: self_define.h map_func.c
	gcc map_func.c -o map_func
user_space: user_space.c self_define.h
	gcc user_space.c -o user_space
kernel_module:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
