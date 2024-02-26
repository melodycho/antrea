package utils

import (
	"fmt"
	"testing"
)

func TestExtractSeconds(t *testing.T) {
	res, err := extractSeconds("Fri Feb 23 06:52:14 UTC 2024 Status changed from unknown to up after 100 seconds")
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(res)
}
