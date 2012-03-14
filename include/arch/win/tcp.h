#ifndef _NETINET_TCP_H
#define _NETINET_TCP_H	1

// Set the packing to a 1 byte boundary
#include "pshpack1.h"

struct tcphdr 
{
	unsigned short source;
    unsigned short dest;
    unsigned long seq;
    unsigned long ack_seq;       
    #  if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned short res1:4;
    unsigned short doff:4;
    unsigned short fin:1;
    unsigned short syn:1;
    unsigned short rst:1;
    unsigned short psh:1;
    unsigned short ack:1;
    unsigned short urg:1;
    unsigned short res2:2;
    #  elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned short doff:4;
    unsigned short res1:4;
    unsigned short res2:2;
    unsigned short urg:1;
    unsigned short ack:1;
    unsigned short psh:1;
    unsigned short rst:1;
    unsigned short syn:1;
    unsigned short fin:1;
    #  endif
    unsigned short window;       
    unsigned short check;
    unsigned short urg_ptr;
};

// Restore the byte boundary back to the previous value
#include <poppack.h>

#endif

