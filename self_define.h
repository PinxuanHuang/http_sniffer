#ifndef _MY_SIMPLE_STRUCT_

#define _MY_SIMPLE_STRUCT_

#define DEV_NAME "simple_dev"

// five tuple
struct ft
{
    // unsigned char sip[4];
    // unsigned char dip[4];
    unsigned char pkt_data[2048];
};

enum ops
{
    GET_FROM_USER = 10,
    SET_TO_USER = 11,
};

#endif
