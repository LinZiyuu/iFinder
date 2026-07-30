package packetrusher

import (
	"os"
	"os/exec"
)

type PacketRusher struct {
	done     chan bool
	isActive bool
	cmd      *exec.Cmd
}

func NewPacketRusher() *PacketRusher {
	return &PacketRusher{
		done:     make(chan bool),
		isActive: false,
	}
}

func (pr *PacketRusher) Activate() {
	if pr.isActive {
		return
	}

	pr.done = make(chan bool)
	pr.isActive = true

	go func() {
		pr.cmd = exec.Command("/root/PacketRusher/packetrusher", "ue")

		go pr.cmd.Run()

		<-pr.done

		if pr.cmd != nil && pr.cmd.Process != nil {
			pr.cmd.Process.Kill()
		}
		pr.isActive = false
	}()
}

func (pr *PacketRusher) Deactivate() {
	if !pr.isActive {
		return
	}

	if pr.cmd != nil && pr.cmd.Process != nil {
		pr.cmd.Process.Signal(os.Interrupt)
		pr.cmd.Wait()
	}
	pr.isActive = false
}

func (pr *PacketRusher) IsActive() bool {
	return pr.isActive
}
