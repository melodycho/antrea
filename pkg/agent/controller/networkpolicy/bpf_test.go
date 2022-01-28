package networkpolicy

import (
	"fmt"
	"net"
	"testing"
)

func TestBPFController_Run(t *testing.T) {
	ip := net.ParseIP("10.10.0.0")
	fmt.Println(ip)
}
