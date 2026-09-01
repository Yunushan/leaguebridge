package wol

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		value string
		want  string
		part  string
	}{
		{value: "AA-BB-CC-DD-EE-FF", want: "aa:bb:cc:dd:ee:ff"},
		{value: "00:11:22:33:44:55", want: "00:11:22:33:44:55"},
		{value: "00:00:00:00:00:00", part: "non-zero"},
		{value: "01:11:22:33:44:55", part: "unicast"},
		{value: "00:11:22:33:44", part: "six"},
		{value: " 00:11:22:33:44:55", part: "whitespace"},
	}
	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			got, err := NormalizeMAC(test.value)
			if test.part == "" {
				if err != nil || got != test.want {
					t.Fatalf("NormalizeMAC() = %q, %v; want %q", got, err, test.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.part) {
				t.Fatalf("NormalizeMAC() error = %v; want %q", err, test.part)
			}
		})
	}
}

func TestBuildPlanCreatesStandardMagicPacket(t *testing.T) {
	plan, err := BuildPlan(Request{
		MAC:                     "00:11:22:33:44:55",
		Destination:             "192.168.1.255",
		Port:                    9,
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.MAC != "00:11:22:33:44:55" || plan.Destination != "192.168.1.255" || plan.Port != 9 {
		t.Fatalf("plan = %+v", plan)
	}
	if len(plan.packet) != magicPacketSize || len(plan.packetBinding) != magicPacketSize {
		t.Fatalf("packet sizes = %d/%d; want %d", len(plan.packet), len(plan.packetBinding), magicPacketSize)
	}
	for index := 0; index < 6; index++ {
		if plan.packet[index] != 0xff {
			t.Fatalf("packet prefix byte %d = %#x; want ff", index, plan.packet[index])
		}
	}
	for repeat := 0; repeat < 16; repeat++ {
		start := 6 + repeat*6
		want := []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
		for index, value := range want {
			if plan.packet[start+index] != value {
				t.Fatalf("packet repeat %d byte %d = %#x; want %#x", repeat, index, plan.packet[start+index], value)
			}
		}
	}
}

func TestBuildPlanRejectsUnsafeRequests(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Request)
		want   string
	}{
		{name: "missing mac", mutate: func(request *Request) { request.MAC = "" }, want: "required"},
		{name: "bad destination", mutate: func(request *Request) { request.Destination = "not-an-ip" }, want: "IPv4"},
		{name: "bad port", mutate: func(request *Request) { request.Port = 0 }, want: "port"},
		{name: "unconfirmed host", mutate: func(request *Request) { request.PhysicalHostConfirmed = false }, want: "physical"},
		{name: "unacknowledged handoff", mutate: func(request *Request) { request.AcceptUnverifiedHandoff = false }, want: "acknowledgement"},
	}
	base := Request{
		MAC:                     "00:11:22:33:44:55",
		Destination:             DefaultDestination,
		Port:                    DefaultPort,
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := base
			test.mutate(&request)
			if _, err := BuildPlan(request); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.want)) {
				t.Fatalf("BuildPlan() error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestExecuteSendsMagicPacketToIPv4Destination(t *testing.T) {
	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.LocalAddr().(*net.UDPAddr).Port
	plan, err := BuildPlan(Request{
		MAC:                     "00:11:22:33:44:55",
		Destination:             "127.0.0.1",
		Port:                    port,
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := Execute(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if err := listener.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, magicPacketSize)
	n, _, err := listener.ReadFromUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	if n != magicPacketSize || !packetMatches(packet, plan.packet) {
		t.Fatalf("received %d-byte packet %x; want %x", n, packet[:n], plan.packet)
	}
}

func TestExecuteRejectsPlanMutation(t *testing.T) {
	plan, err := BuildPlan(Request{
		MAC:                     "00:11:22:33:44:55",
		Destination:             "127.0.0.1",
		Port:                    9,
		PhysicalHostConfirmed:   true,
		AcceptUnverifiedHandoff: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	plan.Destination = "127.0.0.2"
	if err := Execute(context.Background(), plan); err == nil || !strings.Contains(err.Error(), "destination changed") {
		t.Fatalf("Execute() error = %v; want mutation rejection", err)
	}
}
