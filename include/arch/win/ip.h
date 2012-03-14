/* Copyright (C) 1991-1993,1995-2000,2009,2010 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, write to the Free
   Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307 USA.  */

#ifndef __NETINET_IP_H
#define __NETINET_IP_H 1

#include <stdint.h>

typedef uint8_t u_int8_t; 
typedef uint16_t u_int16_t; 
typedef uint32_t u_int32_t;

// Set the packing to a 1 byte boundary
#include "pshpack1.h"

struct timestamp
  {
    u_int8_t len;
    u_int8_t ptr;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int flags:4;
    unsigned int overflow:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int overflow:4;
    unsigned int flags:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    u_int32_t data[9];
  };

/**
	unsigned int:4 causes failure , unsigned char:4 works
*/
struct iphdr
  {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned char ihl:4;
    unsigned char version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    unsigned int version:4;
    unsigned int ihl:4;
#else
# error	"Please fix <bits/endian.h>"
#endif
    u_int8_t tos;
    u_int16_t tot_len;
    u_int16_t id;
    u_int16_t frag_off;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t check;
    u_int32_t saddr;
    u_int32_t daddr;
    /*The options start here. */
  };

// Restore the byte boundary back to the previous value
#include <poppack.h>

#endif /* netinet/ip.h */

