package client_pod

import (
	"fmt"
	"testing"
)

func TestCmd(t *testing.T) {
	fmt.Printf("server=%s; output_file=\"ping_log.txt\"; if [ ! -e \"$output_file\" ]; then touch \"$output_file\"; fi; last_status=\"unknown\"; last_change_time=$(date +%%s); while true; do current_time=$(date +%%s); time_diff=$((current_time - last_change_time)); status=$(nc -vz -w 1 \"$server\" %s > /dev/null && echo \"up\" || echo \"down\"); if [ \"$status\" != \"$last_status\" ]; then echo \"$(date) Status changed from $last_status to $status after ${time_diff} seconds\"; echo \"$(date) Status changed from $last_status to $status after ${time_diff} seconds\" >> \"$output_file\"; last_change_time=$current_time; last_status=$status; fi; sleep 0.1; done\n", "127.0.0.1", "80")
}
