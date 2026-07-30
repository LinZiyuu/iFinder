package pinger

import (
	"fmt"
	"os/exec"
	"strings"
)

func Pinger(dstIP string, nic string) error {
	cmd := exec.Command("ping", "-I", nic, "-c", "3", "-s", "300", dstIP)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ping failed: %v, output: %s", err, output)
	}

	if strings.Contains(string(output), "0 reveived") {
		return fmt.Errorf("no response from %s: %s", dstIP, string(output))
	}

	return nil
}
