obj-m += http_sniffer.o 
obj-m += hashmap.o

# all: map_test kernel_module user_space

# map_test: self_define.h map_func.c map_test.c
# 	gcc map_func.c -c
# 	gcc map_test.c -c
# 	gcc map_func.o map_test.o -o map_test
user_space: user_space.c self_define.h
	gcc user_space.c -o user_space
kernel_module:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
