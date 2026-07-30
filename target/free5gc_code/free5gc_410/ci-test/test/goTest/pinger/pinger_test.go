package pinger

import "testing"

func TestPinger(t *testing.T) {
	err := Pinger("8.8.8.8", "ens33")
	if err != nil {
		t.Errorf("Pinger failed: %v", err)
	}
}
