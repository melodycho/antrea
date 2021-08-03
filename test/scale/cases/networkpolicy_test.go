package cases

import (
	"fmt"
	"testing"
)

func TestGenRand(t *testing.T) {
	for i := 0; i < 10; i++ {
		num := genRandInt() % 100
		fmt.Println(num)
	}
}
