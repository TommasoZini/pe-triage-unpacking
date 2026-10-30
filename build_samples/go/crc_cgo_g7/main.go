// crc_cgo_g7 - Go build variant: CGO_ENABLED=1 (requires a C compiler).
// The checksum is computed by an embedded C function, so the binary is a
// genuine cgo build (contains the C runtime glue, not a pure-Go image).
package main

/*
#include <stddef.h>
static unsigned int c_crc32(const unsigned char *data, size_t len) {
    unsigned int crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int k = 0; k < 8; k++) {
            unsigned int mask = -(crc & 1u);
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}
*/
import "C"

import (
	"fmt"
	"os"
	"strings"
	"unsafe"
)

func crc32C(b []byte) uint32 {
	if len(b) == 0 {
		return uint32(C.c_crc32(nil, 0))
	}
	return uint32(C.c_crc32(
		(*C.uchar)(unsafe.Pointer(&b[0])),
		C.size_t(len(b)),
	))
}

func main() {
	msg := "cgo checksum sample"
	if len(os.Args) > 1 {
		msg = strings.Join(os.Args[1:], " ")
	}
	fmt.Printf("input : %q\n", msg)
	fmt.Printf("crc32 : 0x%08X (computed in C)\n", crc32C([]byte(msg)))
}
