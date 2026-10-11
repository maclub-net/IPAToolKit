#include "bz2.h"
#include <bzlib.h>
#include <stdlib.h>
#include <string.h>

#define CSAP_BZ2_CHUNK_SIZE (256 * 1024)

int csap_bz2_decompress(const uint8_t* compressed, size_t compressed_len,
                        uint8_t** out_output, size_t* out_output_len) {
    if (compressed == NULL || compressed_len == 0 || out_output == NULL || out_output_len == NULL) {
        return -1;
    }

    bz_stream strm;
    memset(&strm, 0, sizeof(strm));

    int ret = BZ2_bzDecompressInit(&strm, 0, 0);
    if (ret != BZ_OK) {
        return -2;
    }

    strm.next_in = (char*)compressed;
    strm.avail_in = (unsigned int)compressed_len;

    size_t capacity = CSAP_BZ2_CHUNK_SIZE;
    size_t total = 0;
    uint8_t* output = (uint8_t*)malloc(capacity);
    if (output == NULL) {
        BZ2_bzDecompressEnd(&strm);
        return -3;
    }

    while (1) {
        if (total == capacity) {
            capacity *= 2;
            uint8_t* newbuf = (uint8_t*)realloc(output, capacity);
            if (newbuf == NULL) {
                free(output);
                BZ2_bzDecompressEnd(&strm);
                return -4;
            }
            output = newbuf;
        }

        strm.next_out = (char*)(output + total);
        strm.avail_out = (unsigned int)(capacity - total);

        ret = BZ2_bzDecompress(&strm);

        total += (capacity - total) - strm.avail_out;

        if (ret == BZ_STREAM_END) {
            break;
        }
        if (ret != BZ_OK) {
            free(output);
            BZ2_bzDecompressEnd(&strm);
            return -5;
        }
    }

    BZ2_bzDecompressEnd(&strm);

    *out_output = output;
    *out_output_len = total;
    return 0;
}
