// mathstats_cgo_g8 - Go build variant: CGO_ENABLED=1 (requires a C compiler).
// Uses libm (sqrt) through cgo, forcing a real C-linked build.
package main

/*
#cgo LDFLAGS: -lm
#include <math.h>
static double c_stddev(const double *v, int n, double mean) {
    double acc = 0.0;
    for (int i = 0; i < n; i++) {
        double d = v[i] - mean;
        acc += d * d;
    }
    return sqrt(acc / (double)n);
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

func main() {
	data := []float64{2, 4, 4, 4, 5, 5, 7, 9}
	var sum float64
	for _, x := range data {
		sum += x
	}
	mean := sum / float64(len(data))
	cv := make([]C.double, len(data))
	for i, x := range data {
		cv[i] = C.double(x)
	}
	sd := C.c_stddev((*C.double)(unsafe.Pointer(&cv[0])), C.int(len(cv)), C.double(mean))
	fmt.Printf("n=%d mean=%.3f stddev=%.3f (sqrt via libm/cgo)\n",
		len(data), mean, float64(sd))
}
