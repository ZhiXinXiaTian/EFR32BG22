#ifndef __LIB_SECURITY_H
#define __LIB_SECURITY_H

#include <memory.h>

#ifdef LIB_SECURITY
#define LIB_SECURITY_EXT
#else
#define LIB_SECURITY_EXT extern
#endif

/*
*********************************************************************************************************
*                                               CRC8
*********************************************************************************************************
*/

/*
*********************************************************************************************************
*                                               MD5
*********************************************************************************************************
*/

#define F(x, y, z) ((x & y) | (~x & z))
#define G(x, y, z) ((x & z) | (y & ~z))
#define H(x, y, z) (x ^ y ^ z)
#define I(x, y, z) (y ^ (x | ~z))
#define ROTATE_LEFT(x, n) ((x << n) | (x >> (32 - n)))
#define FF(a, b, c, d, x, s, ac)  \
    {                             \
        a += F(b, c, d) + x + ac; \
        a = ROTATE_LEFT(a, s);    \
        a += b;                   \
    }
#define GG(a, b, c, d, x, s, ac)  \
    {                             \
        a += G(b, c, d) + x + ac; \
        a = ROTATE_LEFT(a, s);    \
        a += b;                   \
    }
#define HH(a, b, c, d, x, s, ac)  \
    {                             \
        a += H(b, c, d) + x + ac; \
        a = ROTATE_LEFT(a, s);    \
        a += b;                   \
    }
#define II(a, b, c, d, x, s, ac)  \
    {                             \
        a += I(b, c, d) + x + ac; \
        a = ROTATE_LEFT(a, s);    \
        a += b;                   \
    }

typedef struct lib_md5_ctx
{
    unsigned int Count[2];
    unsigned int State[4];
    unsigned char Buffer[64];
} LIB_MD5_CTX;

LIB_SECURITY_EXT void Lib_Md5Init(LIB_MD5_CTX *context);
LIB_SECURITY_EXT void Lib_Md5Update(LIB_MD5_CTX *context, unsigned char *input, unsigned int inputlen);
LIB_SECURITY_EXT void Lib_Md5Final(LIB_MD5_CTX *context, unsigned char digest[16]);
LIB_SECURITY_EXT void Lib_Md5Transform(unsigned int state[4], unsigned char block[64]);
LIB_SECURITY_EXT void Lib_Md5Encode(unsigned char *output, unsigned int *input, unsigned int len);
LIB_SECURITY_EXT void Lib_Md5Decode(unsigned int *output, unsigned char *input, unsigned int len);

#endif