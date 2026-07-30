package test

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	packetRusher "test/packetRusher"
	pinger "test/pinger"
)

func TestULCLTrafficInfluence(t *testing.T) {
	// PacketRusher
	pr := packetRusher.NewPacketRusher()
	pr.Activate()
	defer pr.Deactivate()

	time.Sleep(3 * time.Second)

	// before TI
	t.Run("Before TI", func(t *testing.T) {
		pingN6gwSuccessMecFailed(t)
	})

	// post TI
	tiOperation(t, "put")

	// after TI
	t.Run("After TI", func(t *testing.T) {
		pingN6gwFailedMecSuccess(t)
	})

	// delete TI
	tiOperation(t, "delete")

	// reset TI
	t.Run("Reset TI", func(t *testing.T) {
		pingN6gwSuccessMecFailed(t)
	})

	// flow level ping
	t.Run("Flow Level Ping", func(t *testing.T) {
		pingOneOneOneOne(t)
	})

	// check charging record
	t.Run("Check Charging Record", func(t *testing.T) {
		checkChargingRecord(t)
	})
}

func pingN6gwSuccessMecFailed(t *testing.T) {
	err := pinger.Pinger(N6GW_IP, NIC)
	if err != nil {
		t.Errorf("Ping n6gw failed: expected ping success, but got %v", err)
	}
	err = pinger.Pinger(MEC_IP, NIC)
	if err == nil {
		t.Errorf("Ping mec failed: expected ping failed, but got %v", err)
	}
}

func pingN6gwFailedMecSuccess(t *testing.T) {
	err := pinger.Pinger(N6GW_IP, NIC)
	if err != nil {
		t.Errorf("Ping n6gw failed: expected ping failed, but got %v", err)
	}
	err = pinger.Pinger(MEC_IP, NIC)
	if err == nil {
		t.Errorf("Ping mec failed: expected ping sucess, but got %v", err)
	}
}

func pingOneOneOneOne(t *testing.T) {
	err := pinger.Pinger(ONE_IP, NIC)
	if err != nil {
		t.Errorf("Ping one.one.one.one failed: expected ping success, but got %v", err)
	}
}

func tiOperation(t *testing.T, operation string) {
	cmd := exec.Command("bash", "../api-udr-ti-data-action.sh", operation)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("TI operation failed: expected %s success, but got %v, output: %s", operation, err, output)
	}
	time.Sleep(3 * time.Millisecond)
}

func checkChargingRecord(t *testing.T) {
	cmd := exec.Command("bash", "../api-webconsole-charging-record.sh", "get", "../json/webconsole-login-data.json")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("Get charging record failed: %v, output: %s", err, output)
		return
	}

	outputStr := string(output)

	lines := strings.Split(outputStr, "\n")
	var jsonLine string
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			jsonLine = lines[i]
			break
		}
	}

	var chargingRecords []map[string]interface{}
	if err := json.Unmarshal([]byte(jsonLine), &chargingRecords); err != nil {
		t.Errorf("Failed to parse charging record JSON: %v\nJSON content: %s", err, jsonLine)
		return
	}

	if len(chargingRecords) == 0 {
		t.Error("No charging records found")
		return
	}

	t.Run("Check Session Level Charging Record", func(t *testing.T) {
		checkXLevelChargingRecord(t, chargingRecords, "Session", "")
	})

	t.Run("Check Flow Level Charging Record", func(t *testing.T) {
		checkXLevelChargingRecord(t, chargingRecords, "Flow", "internet")
	})
}

func checkXLevelChargingRecord(t *testing.T, chargingRecords []map[string]interface{}, level string, dnn string) {
	for _, record := range chargingRecords {
		if record["Dnn"] == dnn {
			if record["TotalVol"].(float64) != 0 {
				return
			}
			t.Errorf("%s level charging record is empty", level)
		}
	}
	t.Errorf("No %s level charging record found", level)
}
