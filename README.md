# http_sniffer

It is used to sniff the packet to see whether the packet's application layer is http or not

## Structure

| file           | desc                                                              |
| -------------- | ----------------------------------------------------------------- |
| hashmap.c      | Including implementation of hashmap functions. e.g. set, get, del |
| http_sniffer.c | the kernel module used to parse the packet data                   |
| self_define.h  | define the hashmap struct and ioctl cmd                           |
| user_space.c   | user space program that used to invoke ioctl                      |
| Makefile       | Makefile                                                          |

## Get Started

```shell
make kernel_module
sudo insmod hashmap.ko
sudo insmod http_sniffer.ko
sudo rmmod http_sniffer
sudo rmmod hashmap
```
