#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#define LINE_LEN 16
#define NUM_LINES 8
#define MASK (~ ((LINE_LEN/sizeof(uint32_t)) - 1) )
//AES block size
#define AES_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define AES_CIPHER_ALGO (&aesCipherAlgo)
#define ROUNDS 1
#define BLOCK_SIZE 16

#define LOAD32LE(p) ( \
    ((uint32_t)(((uint8_t *)(p))[0]) << 0) | \
    ((uint32_t)(((uint8_t *)(p))[1]) << 8) | \
    ((uint32_t)(((uint8_t *)(p))[2]) << 16) | \
    ((uint32_t)(((uint8_t *)(p))[3]) << 24))

#define STORE32LE(a, p) \
    ((uint8_t *)(p))[0] = ((uint32_t)(a) >> 0) & 0xFFU, \
    ((uint8_t *)(p))[1] = ((uint32_t)(a) >> 8) & 0xFFU, \
    ((uint8_t *)(p))[2] = ((uint32_t)(a) >> 16) & 0xFFU, \
    ((uint8_t *)(p))[3] = ((uint32_t)(a) >> 24) & 0xFFU
  
#define ROL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))

  typedef int error_t;
#define NO_ERROR 0
#define ERROR_INVALID_PARAMETER 1
#define ERROR_INVALID_KEY_LENGTH 2
  /**
   * @brief AES algorithm context
   **/


  typedef struct
  {
    uint32_t nr;
    uint32_t ek[60];
    uint32_t dk[60];
  } AesContext;

typedef struct cacheline *CacheLine;
struct cacheline {
  void *addr;
  CacheLine prev;
  CacheLine next;
};

struct {
  CacheLine head;
  int reads;
  int misses;
} cache;

//Precalculated table (encryption)
static const uint32_t table_e[256] =
{
  0xA56363C6, 0x847C7CF8, 0x997777EE, 0x8D7B7BF6, 0x0DF2F2FF, 0xBD6B6BD6, 0xB16F6FDE, 0x54C5C591,
  0x50303060, 0x03010102, 0xA96767CE, 0x7D2B2B56, 0x19FEFEE7, 0x62D7D7B5, 0xE6ABAB4D, 0x9A7676EC,
  0x45CACA8F, 0x9D82821F, 0x40C9C989, 0x877D7DFA, 0x15FAFAEF, 0xEB5959B2, 0xC947478E, 0x0BF0F0FB,
  0xECADAD41, 0x67D4D4B3, 0xFDA2A25F, 0xEAAFAF45, 0xBF9C9C23, 0xF7A4A453, 0x967272E4, 0x5BC0C09B,
  0xC2B7B775, 0x1CFDFDE1, 0xAE93933D, 0x6A26264C, 0x5A36366C, 0x413F3F7E, 0x02F7F7F5, 0x4FCCCC83,
  0x5C343468, 0xF4A5A551, 0x34E5E5D1, 0x08F1F1F9, 0x937171E2, 0x73D8D8AB, 0x53313162, 0x3F15152A,
  0x0C040408, 0x52C7C795, 0x65232346, 0x5EC3C39D, 0x28181830, 0xA1969637, 0x0F05050A, 0xB59A9A2F,
  0x0907070E, 0x36121224, 0x9B80801B, 0x3DE2E2DF, 0x26EBEBCD, 0x6927274E, 0xCDB2B27F, 0x9F7575EA,
  0x1B090912, 0x9E83831D, 0x742C2C58, 0x2E1A1A34, 0x2D1B1B36, 0xB26E6EDC, 0xEE5A5AB4, 0xFBA0A05B,
  0xF65252A4, 0x4D3B3B76, 0x61D6D6B7, 0xCEB3B37D, 0x7B292952, 0x3EE3E3DD, 0x712F2F5E, 0x97848413,
  0xF55353A6, 0x68D1D1B9, 0x00000000, 0x2CEDEDC1, 0x60202040, 0x1FFCFCE3, 0xC8B1B179, 0xED5B5BB6,
  0xBE6A6AD4, 0x46CBCB8D, 0xD9BEBE67, 0x4B393972, 0xDE4A4A94, 0xD44C4C98, 0xE85858B0, 0x4ACFCF85,
  0x6BD0D0BB, 0x2AEFEFC5, 0xE5AAAA4F, 0x16FBFBED, 0xC5434386, 0xD74D4D9A, 0x55333366, 0x94858511,
  0xCF45458A, 0x10F9F9E9, 0x06020204, 0x817F7FFE, 0xF05050A0, 0x443C3C78, 0xBA9F9F25, 0xE3A8A84B,
  0xF35151A2, 0xFEA3A35D, 0xC0404080, 0x8A8F8F05, 0xAD92923F, 0xBC9D9D21, 0x48383870, 0x04F5F5F1,
  0xDFBCBC63, 0xC1B6B677, 0x75DADAAF, 0x63212142, 0x30101020, 0x1AFFFFE5, 0x0EF3F3FD, 0x6DD2D2BF,
  0x4CCDCD81, 0x140C0C18, 0x35131326, 0x2FECECC3, 0xE15F5FBE, 0xA2979735, 0xCC444488, 0x3917172E,
  0x57C4C493, 0xF2A7A755, 0x827E7EFC, 0x473D3D7A, 0xAC6464C8, 0xE75D5DBA, 0x2B191932, 0x957373E6,
  0xA06060C0, 0x98818119, 0xD14F4F9E, 0x7FDCDCA3, 0x66222244, 0x7E2A2A54, 0xAB90903B, 0x8388880B,
  0xCA46468C, 0x29EEEEC7, 0xD3B8B86B, 0x3C141428, 0x79DEDEA7, 0xE25E5EBC, 0x1D0B0B16, 0x76DBDBAD,
  0x3BE0E0DB, 0x56323264, 0x4E3A3A74, 0x1E0A0A14, 0xDB494992, 0x0A06060C, 0x6C242448, 0xE45C5CB8,
  0x5DC2C29F, 0x6ED3D3BD, 0xEFACAC43, 0xA66262C4, 0xA8919139, 0xA4959531, 0x37E4E4D3, 0x8B7979F2,
  0x32E7E7D5, 0x43C8C88B, 0x5937376E, 0xB76D6DDA, 0x8C8D8D01, 0x64D5D5B1, 0xD24E4E9C, 0xE0A9A949,
  0xB46C6CD8, 0xFA5656AC, 0x07F4F4F3, 0x25EAEACF, 0xAF6565CA, 0x8E7A7AF4, 0xE9AEAE47, 0x18080810,
  0xD5BABA6F, 0x887878F0, 0x6F25254A, 0x722E2E5C, 0x241C1C38, 0xF1A6A657, 0xC7B4B473, 0x51C6C697,
  0x23E8E8CB, 0x7CDDDDA1, 0x9C7474E8, 0x211F1F3E, 0xDD4B4B96, 0xDCBDBD61, 0x868B8B0D, 0x858A8A0F,
  0x907070E0, 0x423E3E7C, 0xC4B5B571, 0xAA6666CC, 0xD8484890, 0x05030306, 0x01F6F6F7, 0x120E0E1C,
  0xA36161C2, 0x5F35356A, 0xF95757AE, 0xD0B9B969, 0x91868617, 0x58C1C199, 0x271D1D3A, 0xB99E9E27,
  0x38E1E1D9, 0x13F8F8EB, 0xB398982B, 0x33111122, 0xBB6969D2, 0x70D9D9A9, 0x898E8E07, 0xA7949433,
  0xB69B9B2D, 0x221E1E3C, 0x92878715, 0x20E9E9C9, 0x49CECE87, 0xFF5555AA, 0x78282850, 0x7ADFDFA5,
  0x8F8C8C03, 0xF8A1A159, 0x80898909, 0x170D0D1A, 0xDABFBF65, 0x31E6E6D7, 0xC6424284, 0xB86868D0,
  0xC3414182, 0xB0999929, 0x772D2D5A, 0x110F0F1E, 0xCBB0B07B, 0xFC5454A8, 0xD6BBBB6D, 0x3A16162C
};

typedef struct timespec *Time;
//#define DEBUG 1


void touch(CacheLine l)
{
  // Unlink
  l->prev->next = l->next;
  l->next->prev = l->prev;
      
  // Put at head
  l->next = cache.head;
  l->prev = cache.head->prev;
  cache.head->prev = l;
  cache.head->prev->next = l;
  cache.head = l;
}

void init_cache(void)
{
  cache.reads  = 0;
  cache.misses = 0;

  CacheLine line = malloc(sizeof(struct cacheline));
  line->addr = NULL;
  line->next = line;
  line->prev = line;
  cache.head = line;

  for (int ii = 1; ii < NUM_LINES; ii++)
  {
    line = malloc(sizeof(struct cacheline));
    line->next = cache.head;
    line->prev = cache.head->prev;
    cache.head->prev->next = line;
    cache.head->prev = line;
  }
}

void reset_cache(void)
{
  int ii = 0;
  CacheLine cl = cache.head;
  for (; ii < NUM_LINES; ii++, cl = cl->next)
    cl->addr = NULL;
}

uint32_t te(uint8_t index)
{
  int ii = 0;
  void *baseAddr = (void*)&table_e[index & MASK];
  //printf("%02x, %p\n", index, baseAddr);
  CacheLine cl = cache.head;
  cache.reads++;
  
  if ((cache.reads & 0x3) == 0)
    reset_cache();

  for (; ii < NUM_LINES; ii++, cl = cl->next)
  {
    if (baseAddr == cl->addr)
    {
      touch(cl);
      return table_e[index];
    }
  }
  
  reset_cache();
  cl = cache.head->prev;
  cl->addr = baseAddr;
  touch(cl);
  cache.misses++;
  return table_e[index];
}

int cache_hits()
{
  return cache.reads - cache.misses;
}

int cache_misses()
{
  return cache.misses;
}

Time sub(Time start, Time end)
{
  if ((end->tv_nsec - start->tv_nsec) < 0) {
    end->tv_sec  -= start->tv_sec + 1;
    end->tv_nsec -= start->tv_nsec - 1000000000;
  } else {
    end->tv_sec  -= start->tv_sec;
    end->tv_nsec -= start->tv_nsec;
  }
  return end;
}

//Substitution table used by encryption algorithm (S-box)
static const uint8_t sbox[256] =
{
  0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
  0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
  0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
  0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
  0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
  0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
  0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
  0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
  0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
  0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
  0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
  0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
  0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

//Round constant word array
static const uint32_t rcon[11] =
{
  0x00000000,
  0x00000001,
  0x00000002,
  0x00000004,
  0x00000008,
  0x00000010,
  0x00000020,
  0x00000040,
  0x00000080,
  0x0000001B,
  0x00000036
};

static const int S_box[256] = {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};

static const int HW[256] = {0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4,
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 
4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};

/**
 * @brief Key expansion
 * @param[in] context Pointer to the AES context to initialize
 * @param[in] key Pointer to the key
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

error_t aesInit(AesContext *context, const uint8_t *key, size_t keyLen)
{
  uint32_t i;
  uint32_t temp;
  size_t keyScheduleSize;

  //Check parameters
  if(context == NULL || key == NULL)
    return ERROR_INVALID_PARAMETER;

  //Check the length of the key
  if(keyLen == 16)
  {
    //10 rounds are required for 128-bit key
    context->nr = 10;
  }
  else if(keyLen == 24)
  {
    //12 rounds are required for 192-bit key
    context->nr = 12;
  }
  else if(keyLen == 32)
  {
    //14 rounds are required for 256-bit key
    context->nr = 14;
  }
  else
  {
    //Report an error
    return ERROR_INVALID_KEY_LENGTH;
  }

  //Determine the number of 32-bit words in the key
  keyLen /= 4;

  //Copy the original key
  for(i = 0; i < keyLen; i++)
  {
    context->ek[i] = LOAD32LE(key + (i * 4));
  }

  //The size of the key schedule depends on the number of rounds
  keyScheduleSize = 4 * (context->nr + 1);

  //Generate the key schedule (encryption)
  for(i = keyLen; i < keyScheduleSize; i++)
  {
    //Save previous word
    temp = context->ek[i - 1];

    //Apply transformation
    if((i % keyLen) == 0)
    {
      context->ek[i] = sbox[(temp >> 8) & 0xFF];
      context->ek[i] |= (sbox[(temp >> 16) & 0xFF] << 8);
      context->ek[i] |= (sbox[(temp >> 24) & 0xFF] << 16);
      context->ek[i] |= (sbox[temp & 0xFF] << 24);
      context->ek[i] ^= rcon[i / keyLen];
    }
    else if(keyLen > 6 && (i % keyLen) == 4)
    {
      context->ek[i] = sbox[temp & 0xFF];
      context->ek[i] |= (sbox[(temp >> 8) & 0xFF] << 8);
      context->ek[i] |= (sbox[(temp >> 16) & 0xFF] << 16);
      context->ek[i] |= (sbox[(temp >> 24) & 0xFF] << 24);
    }
    else
    {
      context->ek[i] = temp;
    }

    //Update the key schedule
    context->ek[i] ^= context->ek[i - keyLen];
  }

  //No error to report
  return NO_ERROR;
}


/**
 * @brief Encrypt a 16-byte block using AES algorithm
 * @param[in] context Pointer to the AES context
 * @param[in] input Plaintext block to encrypt
 * @param[out] output Ciphertext block resulting from encryption
 **/

void aesEncryptBlock(AesContext *context, const uint8_t *input, uint8_t *output)
{
  uint32_t i;
  uint32_t s0;
  uint32_t s1;
  uint32_t s2;
  uint32_t s3;
  uint32_t t0;
  uint32_t t1;
  uint32_t t2;
  uint32_t t3;
  uint32_t temp;

  //Copy the plaintext to the state array
  s0 = LOAD32LE(input + 0);
  s1 = LOAD32LE(input + 4);
  s2 = LOAD32LE(input + 8);
  s3 = LOAD32LE(input + 12);

  //Initial round key addition
  s0 ^= context->ek[0];
  s1 ^= context->ek[1];
  s2 ^= context->ek[2];
  s3 ^= context->ek[3];

  //The number of rounds depends on the key length
  for(i = 1; i < context->nr; i++)
  {
    //Apply round function
    t0 = te(s0 & 0xFF);
    t1 = te(s1 & 0xFF);
    t2 = te(s2 & 0xFF);
    t3 = te(s3 & 0xFF);

    temp = te((s1 >> 8) & 0xFF);
    t0 ^= ROL32(temp, 8);
    temp = te((s2 >> 8) & 0xFF);
    t1 ^= ROL32(temp, 8);
    temp = te((s3 >> 8) & 0xFF);
    t2 ^= ROL32(temp, 8);
    temp = te((s0 >> 8) & 0xFF);
    t3 ^= ROL32(temp, 8);

    temp = te((s2 >> 16) & 0xFF);
    t0 ^= ROL32(temp, 16);
    temp = te((s3 >> 16) & 0xFF);
    t1 ^= ROL32(temp, 16);
    temp = te((s0 >> 16) & 0xFF);
    t2 ^= ROL32(temp, 16);
    temp = te((s1 >> 16) & 0xFF);
    t3 ^= ROL32(temp, 16);
    
    temp = te((s3 >> 24) & 0xFF);
    t0 ^= ROL32(temp, 24);
    temp = te((s0 >> 24) & 0xFF);
    t1 ^= ROL32(temp, 24);
    temp = te((s1 >> 24) & 0xFF);
    t2 ^= ROL32(temp, 24);
    temp = te((s2 >> 24) & 0xFF);
    t3 ^= ROL32(temp, 24);

    //Round key addition
    s0 = t0 ^ context->ek[i * 4];
    s1 = t1 ^ context->ek[i * 4 + 1];
    s2 = t2 ^ context->ek[i * 4 + 2];
    s3 = t3 ^ context->ek[i * 4 + 3];
  }

  //The last round differs slightly from the first rounds
  t0 = sbox[s0 & 0xFF];
  t0 |= sbox[(s1 >> 8) & 0xFF] << 8;
  t0 |= sbox[(s2 >> 16) & 0xFF] << 16;
  t0 |= sbox[(s3 >> 24) & 0xFF] << 24;

  t1 = sbox[s1 & 0xFF];
  t1 |= sbox[(s2 >> 8) & 0xFF] << 8;
  t1 |= sbox[(s3 >> 16) & 0xFF] << 16;
  t1 |= sbox[(s0 >> 24) & 0xFF] << 24;

  t2 = sbox[s2 & 0xFF];
  t2 |= sbox[(s3 >> 8) & 0xFF] << 8;
  t2 |= sbox[(s0 >> 16) & 0xFF] << 16;
  t2 |= sbox[(s1 >> 24) & 0xFF] << 24;

  t3 = sbox[s3 & 0xFF];
  t3 |= sbox[(s0 >> 8) & 0xFF] << 8;
  t3 |= sbox[(s1 >> 16) & 0xFF] << 16;
  t3 |= sbox[(s2 >> 24) & 0xFF] << 24;

  //Last round key addition
  s0 = t0 ^ context->ek[context->nr * 4];
  s1 = t1 ^ context->ek[context->nr * 4 + 1];
  s2 = t2 ^ context->ek[context->nr * 4 + 2];
  s3 = t3 ^ context->ek[context->nr * 4 + 3];

  //The final state is then copied to the output
  STORE32LE(s0, output + 0);
  STORE32LE(s1, output + 4);
  STORE32LE(s2, output + 8);
  STORE32LE(s3, output + 12);
}

void shuffle(int* array, int size) {
    for (int i = size - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        // 交换 array[i] 和 array[j]
        int temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

int aes_internal(int inputdata, int key){
    return S_box[inputdata ^ key];
}

int main(int argc, char* argv[])
{
  uint8_t output[BLOCK_SIZE];
  uint8_t key[] = {0x83, 0x39, 0x71, 0x90, 0xAD, 0x6E, 0x9D, 0x77, 0x78, 0xED, 0xCB, 0x38, 0xE7, 0x60, 0x97, 0x1D, };
  uint8_t input[] = {0x0D, 0xDE, 0xE6, 0xBA, 0x23, 0x89, 0x0A, 0x5D, 0xF6, 0x0A, 0x5C, 0x12, 0x69, 0x87, 0x00, 0x37, };
  uint8_t tkey[16];
  int percent[7] = {0, 2, 5, 7, 10, 12, 15};
  int index[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
  int round = 100;
  int sample = 1000;
  
  for (int sam=0; sam<sample; sam++){
    printf("%d ", sam);
    srand(time(NULL));
    remove("output.txt");
    FILE *file = fopen("output.txt", "a");
    for (int j=0; j < 7; j++) {
      // 取不同的percent
      for (int k = 0; k < round; k++) {
        // 打乱数组
        memcpy(tkey, key, sizeof(key));
        shuffle(index, 16);
        //printf("percent为 %d 下, 第 %d 次采样: ", j, k + 1);
        for (int i = 0; i < 16 - percent[j]; i++) {
            // 这里实际上是变的数组下标
            tkey[index[i]] = rand() % 256;
        }
        AesContext *ctxt = malloc(sizeof(AesContext));
        init_cache();
        aesInit(ctxt, tkey, BLOCK_SIZE);
        for (int ii = 0; ii < ROUNDS; ii++)
        {
          aesInit(ctxt, tkey, BLOCK_SIZE);
          aesEncryptBlock(ctxt, input, output);
        }

        int num = 0; 
        for (int i = 0; i < 16; i++){
          int HW_weight = HW[aes_internal(input[i], tkey[i])];
          num = num + HW_weight;
        }
        
        fprintf(file, "%d,%d,%d\n", percent[j], cache_hits(), num);
        free(ctxt);
        ctxt = NULL;

        /*printf("tkey结果:\n");
        for (int i = 0; i < 16; i++) {
          printf("%d ", tkey[i]);
      }
      printf("\n");*/
      }
    }
    fclose(file);
    system("python cal.py");
  }
  
  /*srand(time(NULL));
  for (int i = 0; i < 16; i++) {
        tkey[i] = rand() % 256; // 生成0到255之间的随机数
    }
  
  AesContext *ctxt = malloc(sizeof(AesContext));
  init_cache();
  aesInit(ctxt, tkey, BLOCK_SIZE);
  for (int ii = 0; ii < ROUNDS; ii++)
  {
    aesInit(ctxt, tkey, BLOCK_SIZE);
    aesEncryptBlock(ctxt, input, output);
    printf("%d\n", cache_hits());
    printf("%d\n", cache_hits() + 25 * cache_misses());
  }*/
  return 0;
}






