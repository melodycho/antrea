package utils

import (
	"fmt"
	"testing"
)

func TestExtractSeconds(t *testing.T) {
	testCases := []struct {
		name string
		log  string
		key  string
	}{
		{
			name: "unknown to up",
			log:  "1234567 Status changed from unknown to up after 100 seconds",
			key:  "to up",
		},
		{
			name: "down to up",
			log:  "12345678 Status changed from down to up after 100 seconds",
			key:  "to up",
		},
		{
			name: "unknown to down",
			log:  "1709868559530201288 Status changed from unknown to down after 1007982937 nanoseconds",
			key:  "to down",
		},
	}
	for _, tc := range testCases {
		res, err := extractNanoseconds(tc.log, tc.key)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println(res)
	}
}
