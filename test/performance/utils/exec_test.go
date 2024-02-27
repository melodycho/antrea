package utils

import (
	"fmt"
	"testing"
)

func TestExtractSeconds(t *testing.T) {
	testCases := []struct {
		name string
		log  string
	}{
		{
			name: "",
			log:  "1234567 Status changed from unknown to up after 100 seconds",
		},
		{
			name: "",
			log:  "12345678 Status changed from down to up after 100 seconds",
		},
	}
	for _, tc := range testCases {
		res, err := extractNanoseconds(tc.log)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(res)
	}

}
