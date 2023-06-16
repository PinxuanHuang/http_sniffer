# http_sniffer

It is used to sniff the http packets and flow

## Structure

| file           | desc                                                                                  |
| -------------- | ------------------------------------------------------------------------------------- |
| hashmap.c      | Including implementation of flow table hashmap functions. e.g. set, get, del          |
| http_sniffer.c | the kernel module used to parse the packet data and transfer the data to user space   |
| self_define.h  | define the flow table hashmap struct and ioctl cmd                                    |
| user_space.c   | user space program that used to invoke ioctl and write the packet data to pcap format |
| Makefile       | Makefile                                                                              |

## Get Started

You need two virtual machine, one of them to be client and the other one to be the router

```shell
./set_iptables # run this on router
ethtool -K <dev> gro off # also run this on router for both network interface. It's already in the set_iptables file, so just replace the device name
make kernel_module
make user_space
sudo insmod my_http_sniffer.ko
./user_space
# send requests from the client, and stop the agent with ctrl + c
sudo rmmod my_http_sniffer
```

# Hint

- my kernel version is 5.15.0
- It can work under multi core(cpu) now.

# Environment

client(apache bench) ---- server(kernel module) ---- server(apache server)
