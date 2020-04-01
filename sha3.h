#ifndef SHA3_H
#define SHA3_H


#ifdef _WIN32
  /* Windows - set up dll import/export decorators. */
# if defined(BUILDING_SHA3_SHARED)
    /* Building shared library. */
#   define SHA3_EXPORT __declspec(dllexport)
# elif defined(USING_SHA3_SHARED)
    /* Using shared library. */
#   define SHA3_EXPORT __declspec(dllimport)
# else
    /* Building static library. */
#   define SHA3_EXPORT /* nothing */
# endif
#elif __GNUC__ >= 4
# define SHA3_EXPORT __attribute__((visibility("default")))
#else
# define SHA3_EXPORT /* nothing */
#endif


/* -------------------------------------------------------------------------
 * Works when compiled for either 32-bit or 64-bit targets, optimized for 
 * 64 bit.
 *
 * Canonical implementation of Init/Update/Finalize for SHA-3 byte input. 
 *
 * SHA3-224, SHA3-256, SHA3-384, SHA-512 are implemented.
 *
 * Based on code from http://keccak.noekeon.org/ .
 *
 * I place the code that I wrote into public domain, free to use. 
 *
 * I would appreciate if you give credits to this work if you used it to 
 * write or test * your code.
 *
 * Aug 2015. Andrey Jivsov. crypto@brainhub.org
 * ---------------------------------------------------------------------- */

/* 'Words' here refers to uint64_t */
#define SHA3_KECCAK_SPONGE_WORDS \
	(((1600)/8/*bits to byte*/)/sizeof(uint64_t))
typedef struct sha3_context_ {
    uint64_t saved;             /* the portion of the input message that we
                                 * didn't consume yet */
    union {                     /* Keccak's state */
        uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
        uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
    };
    unsigned byteIndex;         /* 0..7--the next byte after the set one
                                 * (starts from 0; 0--none are buffered) */
    unsigned wordIndex;         /* 0..24--the next word to integrate input
                                 * (starts from 0) */
    unsigned capacityWords;     /* the double size of the hash output in
                                 * words (e.g. 16 for Keccak 512) */
} sha3_context;

enum SHA3_FLAGS {
    SHA3_FLAGS_NONE=0,
    SHA3_FLAGS_KECCAK=1
};

enum SHA3_RETURN {
    SHA3_RETURN_OK=0,
    SHA3_RETURN_BAD_PARAMS=1
};
typedef enum SHA3_RETURN sha3_return_t;

/* For Init or Reset call these: */
SHA3_EXPORT sha3_return_t sha3_Init(void *priv, unsigned bitSize);

SHA3_EXPORT void sha3_Init224(void *priv);
SHA3_EXPORT void sha3_Init256(void *priv);
SHA3_EXPORT void sha3_Init384(void *priv);
SHA3_EXPORT void sha3_Init512(void *priv);

SHA3_EXPORT enum SHA3_FLAGS sha3_SetFlags(void *priv, enum SHA3_FLAGS);

SHA3_EXPORT void sha3_Update(void *priv, void const *bufIn, size_t len);

SHA3_EXPORT void const *sha3_Finalize(void *priv);

/* Single-call hashing */
SHA3_EXPORT sha3_return_t sha3_HashBuffer( 
    unsigned bitSize,   /* 256, 384, 512 */
    enum SHA3_FLAGS flags, /* SHA3_FLAGS_NONE or SHA3_FLAGS_KECCAK */
    const void *in, unsigned inBytes, 
    void *out, unsigned outBytes );     /* up to bitSize/8; truncation OK */

#endif
