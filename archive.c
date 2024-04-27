#include "archive.h"
// https://github.com/Zunawe/md5-c/blob/main/md5.c
/*
 * Derived from the RSA Data Security, Inc. MD5 Message-Digest Algorithm
 * and modified slightly to be functionally identical but condensed into control structures.
 */
struct md5_ctx {
  uint64_t size;
  uint32_t buffer[4];
  uint8_t input[64];
  uint8_t digest[16];
};

static uint32_t S[] = {
  7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

static uint32_t K[] = {
  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
  0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
  0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
  0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
  0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
  0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
  0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
  0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
  0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
  0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
  0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
  0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
  0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
  0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
  0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
  0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};
/*
 * Padding used to make the size (in bits) of the input congruent to 448 mod 512
 */
static uint8_t PADDING[] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
/*
 * Bit-manipulation functions defined by the MD5 algorithm
 */
#define F(X, Y, Z) ((X & Y) | (~X & Z))
#define G(X, Y, Z) ((X & Z) | (Y & ~Z))
#define H(X, Y, Z) (X ^ Y ^ Z)
#define I(X, Y, Z) (Y ^ (X | ~Z))
/*
 * Rotates a 32-bit word left by n bits
 */
static uint32_t rotateLeft(uint32_t x, uint32_t n){
  return (x << n) | (x >> (32 - n));
}
/*
 * Initialize a context
 */
static void md5_init(struct md5_ctx *ctx){
  ctx->size = (uint64_t)0;
  ctx->buffer[0] = (uint32_t)0x67452301;
  ctx->buffer[1] = (uint32_t)0xefcdab89;
  ctx->buffer[2] = (uint32_t)0x98badcfe;
  ctx->buffer[3] = (uint32_t)0x10325476;
}
/*
 * Step on 512 bits of input with the main MD5 algorithm.
 */
static void md5_step(uint32_t *buffer, uint32_t *input){
  uint32_t AA = buffer[0];
  uint32_t BB = buffer[1];
  uint32_t CC = buffer[2];
  uint32_t DD = buffer[3];

  uint32_t E;
  unsigned int j;

  for(unsigned int i = 0; i < 64; ++i){
    switch(i / 16){
      case 0: {
        E = F(BB, CC, DD);
        j = i;
      } break;
      case 1: {
        E = G(BB, CC, DD);
        j = ((i * 5) + 1) % 16;
      } break;
      case 2: {
        E = H(BB, CC, DD);
        j = ((i * 3) + 5) % 16;
      } break;
      default: {
        E = I(BB, CC, DD);
        j = (i * 7) % 16;
      } break;
    }

    uint32_t temp = DD;
    DD = CC;
    CC = BB;
    BB = BB + rotateLeft(AA + E + K[i] + input[j], S[i]);
    AA = temp;
  }

  buffer[0] += AA;
  buffer[1] += BB;
  buffer[2] += CC;
  buffer[3] += DD;
}
/*
 * Add some amount of input to the context
 *
 * If the input fills out a block of 512 bits, apply the algorithm (md5Step)
 * and save the result in the buffer. Also updates the overall size.
 */
static void md5_update(
  struct md5_ctx *ctx, uint8_t *input_buffer, size_t input_len
) {
  uint32_t input[16];
  unsigned int offset = ctx->size % 64;
  ctx->size += (uint64_t)input_len;

  // Copy each byte in input_buffer into the next space in our context input
  for(unsigned int i = 0; i < input_len; ++i){
    ctx->input[offset++] = (uint8_t)*(input_buffer + i);

    // If we've filled our context input, copy it into our local array input
    // then reset the offset to 0 and fill in a new buffer.
    // Every time we fill out a chunk, we run it through the algorithm
    // to enable some back and forth between cpu and i/o
    if(offset % 64 == 0){
      for(unsigned int j = 0; j < 16; ++j){
        // Convert to little-endian
        // The local variable `input` our 512-bit chunk separated into 32-bit words
        // we can use in calculations
        input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
                   (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
                   (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
                   (uint32_t)(ctx->input[(j * 4)]);
      }
      md5_step(ctx->buffer, input);
      offset = 0;
    }
  }
}
/*
 * Pad the current input to get to 448 bytes, append the size in bits to the very end,
 * and save the result of the final iteration into digest.
 */
static void md5_finalize(struct md5_ctx *ctx){
  uint32_t input[16];
  unsigned int offset = ctx->size % 64;
  unsigned int padding_length = offset < 56 ? 56 - offset : (56 + 64) - offset;

  // Fill in the padding and undo the changes to size that resulted from the update
  md5_update(ctx, PADDING, padding_length);
  ctx->size -= (uint64_t)padding_length;

  // Do a final update (internal to this function)
  // Last two 32-bit words are the two halves of the size (converted from bytes to bits)
  for(unsigned int j = 0; j < 14; ++j){
    input[j] = (uint32_t)(ctx->input[(j * 4) + 3]) << 24 |
               (uint32_t)(ctx->input[(j * 4) + 2]) << 16 |
               (uint32_t)(ctx->input[(j * 4) + 1]) <<  8 |
               (uint32_t)(ctx->input[(j * 4)]);
  }
  input[14] = (uint32_t)(ctx->size * 8);
  input[15] = (uint32_t)((ctx->size * 8) >> 32);

  md5_step(ctx->buffer, input);

  // Move the result into digest (convert from little-endian)
  for(unsigned int i = 0; i < 4; ++i){
    ctx->digest[(i * 4) + 0] = (uint8_t)((ctx->buffer[i] & 0x000000FF));
    ctx->digest[(i * 4) + 1] = (uint8_t)((ctx->buffer[i] & 0x0000FF00) >>  8);
    ctx->digest[(i * 4) + 2] = (uint8_t)((ctx->buffer[i] & 0x00FF0000) >> 16);
    ctx->digest[(i * 4) + 3] = (uint8_t)((ctx->buffer[i] & 0xFF000000) >> 24);
  }
}
#define IS_CONT(b) (((unsigned char)(b) & 0xC0) == 0x80)
static void MD5(uint8_t * input, size_t len, uint8_t * result) {
  struct md5_ctx ctx;
  md5_init(&ctx);
  md5_update(&ctx, input, len);
  md5_finalize(&ctx);
  memcpy(result, ctx.digest, 16);
}

static int num_bytes_in_utf8_sequence(unsigned char c) {
  if (c == 0xC0 || c == 0xC1 || c > 0xF4 || IS_CONT(c)) return 0;
  if ((c & 0x80) == 0) return 1;
  if ((c & 0xE0) == 0xC0) return 2;
  if ((c & 0xF0) == 0xE0) return 3;
  if ((c & 0xF8) == 0xF0) return 4;
  return 0;
}

static int verify_utf8_sequence(const unsigned char * str, int * len) {
  unsigned int cp = 0;
  *len = num_bytes_in_utf8_sequence(str[0]);
  if (*len == 1) {
    cp = str[0];
  } else if (*len == 2 && IS_CONT(str[1])) {
    cp = str[0] & 0x1f;
    cp = (cp << 6) | (str[1] & 0x3f);
  } else if (*len == 3 && IS_CONT(str[1]) && IS_CONT(str[2])) {
    cp = ((unsigned char)str[0]) & 0xf;
    cp = (cp << 6) | (str[1] & 0x3f);
    cp = (cp << 6) | (str[2] & 0x3f);
  } else if (*len == 4 && IS_CONT(str[1]) && IS_CONT(str[2]) && IS_CONT(str[3])) {
    cp = str[0] & 0x7;
    cp = (cp << 6) | (str[1] & 0x3f);
    cp = (cp << 6) | (str[2] & 0x3f);
    cp = (cp << 6) | (str[3] & 0x3f);
  } else {
    return -1;
  }
  if ((cp < 0x80 && *len > 1) || (cp < 0x800 && *len > 2) || (cp < 0x10000 && *len > 3)) {
    return -1;
  }
  if (cp > 0x10FFFF) return -1;
  if (cp >= 0xD800 && cp <= 0xDFFF) return -1;
  return 0;
}

static int is_valid_utf8(const char * str, size_t len) {
  int bytes = 0;
  const char * end = str + len;
  while (str < end) {
    if (verify_utf8_sequence((const unsigned char *)str, &bytes) != 0) {
      return -1;
    }
    str += bytes;
  }
  return 0;
}

/*This file implements all the data structures and operations related to the
  chat archive. This means the structure that stores an archive, as well as the
  operations related to changing it. It also contains all the operations related
  to incoming potential archives, such as hash validation and whatnot.*/

/*parses the message, checking if all characters are valid (printable). For
  valid messages, returns number of characters in the message. Returns 0 for
  invalid strings (empty or containing illegal characters)*/
int parse_message (uint8_t *msg) {
  int count = 0;
  uint8_t * p = msg;
  /*iterate over characters in string, validating (and counting) each*/
  while (*p) {
    count++;
    p++;
  }
  p = msg + count - 1;
  while(*p == '\r' || *p == '\n' || *p == '\t' || *p == ' ' || *p == '\v' || *p == '\f') {
    *p = '\0';
    count--;
    p--;
  }
  if (is_valid_utf8((const char *)msg, count) < 0) return 0;
  return count;
}

/*Attempts to insert message 'msg' in the given chat archive. To do so, we
  check if the message is valid, then mine a 16 byte code that generates a valid
  MD5 hash for the string. Then format the string for the entire msg+metadata
  properly, and include it in the archive structure, updating it accordingly.
  Returns 1 if message was added successfully, 0 otherwise.

  Note that we do not validate the archive before attempting to add the message,
  we just assume it is already valid, since all archives are validated when
  initially received.*/
int add_message (struct archive *arch, uint8_t *msg) {
  uint16_t len;
  uint8_t *code, *md5;

  /*parse message and get length, return if message is invalid*/
  len = parse_message(msg);
  if (len == 0) {
    return 0;
  }

  /*print message back to user*/
  int i;
  fprintf(stdout, "\nMessage length = %d\nContent: ", len);
  for (i = 0; i < len; i++) {
    fprintf(stdout, "%c", msg[i]);
  }
  fprintf(stdout, "\n");

  /*realloc archive string to fit the new message, then concatenate it*/
  arch->str = realloc(arch->str, arch->len + len + 33);
  *(arch->str + arch->len) = len;
  memcpy(arch->str + arch->len + 1, msg, len);

  /*get pointers to the beginning of the code/md5 hash sections of sequence*/
  code = arch->str + arch->len + len + 1;
  md5 = code+16;

  /*128bit pointer for hash comparison, 16bit pointer for 2 0-byte check*/
  unsigned __int128 *mineptr = (unsigned __int128*) code;
  uint16_t *check = (uint16_t*) md5;

  /*mine a code that generates a valid MD5 hash*/
  *mineptr = (unsigned __int128) 0;
  while (1) {
    MD5(arch->str + arch->offset, (arch->len - arch->offset + len + 17), md5);
    /*found it (first 2 bytes are 0)*/
    if (*check == 0) {
      break;
    }
    *mineptr += 1;
  }

  /*print the mined code and message hash*/
  fprintf(stdout, "code: ");
  for (i = 0; i < 16; i++) {
    fprintf(stdout, "%02x", *(code+i));
  }
  fprintf(stdout, "\nmd5: ");
  for (i = 0; i < 16; i++) {
    fprintf(stdout, "%02x", *(md5+i));
  }
  fprintf(stdout, "\n\n");

  /*update archive size and length, and offset if necessary*/
  arch->size += 1;
  arch->len += len+33;
  if (arch->size >= 20) {
    arch->offset += *(arch->str+arch->offset)+33;
  }

  /*update archive size byte representation*/
  uint8_t *aux = arch->str+1;
  uint32_t old_size=((aux[0] << 24) | (aux[1] << 16) | (aux[2] << 8) | aux[3]);
  old_size++;
  aux[0] = (old_size >> 24) & 0xFF;
  aux[1] = (old_size >> 16) & 0xFF;
  aux[2] = (old_size >> 8) & 0xFF;
  aux[3] = old_size & 0xFF;

  return 1;
}

/*Given an input archive, validates the MD5 hashes of all of its messages, and
  returns whether the entire archive is valid or not. 1 -> valid archive, 0
  otherwise.*/
int is_valid (struct archive *arch) {
  uint8_t *begin, *end, md5[16];
  unsigned __int128 *calc_hash, *orig_hash;

  /*skip message type/size bytes*/
  begin = arch->str+5;
  end = arch->str+5;

  /*our calculated hash is always at the same memory address*/
  calc_hash = (unsigned __int128*) md5;

  /*now let's iterate over every message in the archive*/
  uint32_t i, md5len = 0;
  for (i = 1; i <= arch->size; i++) {
    /*first compute the length of the current message*/
    uint8_t len = *end;

    /*iterate to end of message, and keep track of how many bytes we'll hash*/
    end += len+17;
    md5len += len+17;

    /*check first 2 bytes of hash, we use a 2 byte pointer to simplify things*/
    uint16_t *f2bytes = (uint16_t*) end;
    if (*f2bytes != 0) {
      fprintf(stderr, "Non-zero bytes in MD5 Hash. Invalid archive!\n");
      return 0;
    }

    /*update offset starting from 20th message*/
    if (i > 19) {
      arch->offset += ((*begin) + 33);
    }

    /*if sequence is over 20 messages long, remove first message from md5 input
    string, and recompute its length*/
    if (i > 20) {
      md5len -= ((*begin) + 33);
      begin += ((*begin) + 33);
    }

    /*calculate hash for byte sequence, and compare with original hash*/
    MD5(begin, md5len, md5);

    orig_hash = (unsigned __int128*) end;

    if (*calc_hash != *orig_hash) {
      fprintf(stderr, "Hash Mismatch! Invalid archive.\n");
      return 0;
    }

    /*update end pointer past the md5 hash, and update md5 input string length*/
    end += 16;
    md5len += 16;
  }
  return 1;
}

/*prints an archive to given stream, for either debugging or updating archive*/
void print_archive (struct archive *arch, FILE *stream) {
  uint8_t *ptr;
  uint32_t size;

  ptr = arch->str;
  size = arch->size;

  fprintf(stream, "\n----------ARCHIVE BEGINNING----------\n");
  /*message type and syze bytes*/
  fprintf(stream, "size: %u, length: %u\n", arch->size, arch->len);

  ptr+=5;

  /*loop through messages*/
  uint32_t i, j;
  for (i = 0; i < size; i++) {
    uint8_t len;
    len = *ptr++;

    fprintf(stream, "msg[%d]: ", len);

    /*message content*/
    for (j = 0; j < len; j++, ptr++) {
      fprintf(stream, "%c", *ptr);
    }

    /*16 byte hashing code*/
    fprintf(stream, "\ncode: ");
    for (j = 0; j < 16; j++, ptr++) {
      fprintf(stream, "%02x", *ptr);
    }

    /*16 byte MD5 hash*/
    fprintf(stream, "\nmd5: ");
    for (j = 0; j < 16; j++, ptr++) {
      fprintf(stream, "%02x", *ptr);
    }
    fprintf(stream, "\n");
  }

  fprintf(stream, "---------- ARCHIVE FINISH ----------\n");
}

/*Initializes a new archive structure, and returns it. New archives have size 0,
  so that any new valid archive can overwrite them. Its string representation is
  initially 5 characters long, containing only the message type and the 4 bytes
  indicating amount of messages (which is obviously 0).
  Offset is initially 5, since there are no messages in the archive (obvs), and
  we ignore the type+size bytes*/
struct archive *init_archive() {
  struct archive *newarchive;

  newarchive = (struct archive*) malloc(sizeof(struct archive));

  uint8_t *str = (uint8_t*) malloc(5);
  str[0] = 4;
  str[1] = str[2] = str[3] = str[4] = 0;
  newarchive->str = str;
  newarchive->offset = 5;

  newarchive->len = 5;
  newarchive->size = 0;

  return newarchive;
}
