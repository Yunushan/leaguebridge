// Package wol provides a small, shell-free Wake-on-LAN sender for the
// Linux/BSD physical-host handoff. It only emits a standard magic packet; it
// does not start software, authenticate to a host, or inspect League/Vanguard.
package wol

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"syscall"
)

const (
	DefaultDestination = "255.255.255.255"
	DefaultPort        = 9
	maxDestinationSize = 64
	magicPacketSize    = 6 + 16*6
)

// Request contains the explicit destination and handoff acknowledgements
// required before a magic packet may be sent.
type Request struct {
	MAC                     string
	Destination             string
	Port                    int
	PhysicalHostConfirmed   bool
	AcceptUnverifiedHandoff bool
}

// Plan is a validated, fixed Wake-on-LAN operation. The packet itself is kept
// private so a decoded or mutated JSON value cannot be replayed as launch
// authority.
type Plan struct {
	MAC         string   `json:"mac"`
	Destination string   `json:"destination"`
	Port        int      `json:"port"`
	Warnings    []string `json:"warnings"`

	validated      bool
	mac            string
	destination    string
	port           int
	packet         []byte
	packetBinding  []byte
	requestBinding requestBinding
}

type requestBinding struct {
	mac         string
	destination string
	port        int
}

// NormalizeMAC validates a six-byte unicast Ethernet address and returns its
// canonical lower-case colon-separated form.
func NormalizeMAC(value string) (string, error) {
	if value == "" {
		return "", errors.New("Wake-on-LAN MAC address is required")
	}
	if strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t") {
		return "", errors.New("Wake-on-LAN MAC address must not contain whitespace or control characters")
	}
	address, err := net.ParseMAC(value)
	if err != nil || len(address) != 6 {
		return "", errors.New("Wake-on-LAN MAC address must contain exactly six hexadecimal octets")
	}
	allZero := true
	for _, octet := range address {
		if octet != 0 {
			allZero = false
			break
		}
	}
	if allZero || address[0]&1 != 0 {
		return "", errors.New("Wake-on-LAN MAC address must be a non-zero unicast address")
	}
	return address.String(), nil
}

// NormalizeDestination validates an IPv4 destination. Broadcast and directed
// broadcast addresses are supported, as are unicast destinations used by
// networks that do not forward limited broadcasts.
func NormalizeDestination(value string) (string, error) {
	if value == "" {
		value = DefaultDestination
	}
	if len(value) > maxDestinationSize || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\x00\r\n\t") {
		return "", errors.New("Wake-on-LAN destination must be a clean IPv4 address")
	}
	address := net.ParseIP(value)
	if address == nil || address.To4() == nil {
		return "", errors.New("Wake-on-LAN destination must be an IPv4 address")
	}
	return address.To4().String(), nil
}

// BuildPlan validates a Wake-on-LAN request and constructs its standard
// 102-byte magic packet without performing network I/O.
func BuildPlan(request Request) (Plan, error) {
	mac, err := NormalizeMAC(request.MAC)
	if err != nil {
		return Plan{}, err
	}
	destination, err := NormalizeDestination(request.Destination)
	if err != nil {
		return Plan{}, err
	}
	if request.Port < 1 || request.Port > 65535 {
		return Plan{}, fmt.Errorf("Wake-on-LAN port must be between 1 and 65535, got %d", request.Port)
	}
	if !request.PhysicalHostConfirmed {
		return Plan{}, errors.New("Wake-on-LAN target is not confirmed as a physical Windows PC or Mac; LeagueBridge refuses VM handoffs")
	}
	if !request.AcceptUnverifiedHandoff {
		return Plan{}, errors.New("Wake-on-LAN is an unverified physical-host handoff, not local Linux/BSD support; pass explicit acknowledgement to continue")
	}

	packet := magicPacket(mac)
	return Plan{
		MAC:         mac,
		Destination: destination,
		Port:        request.Port,
		Warnings: []string{
			"Wake-on-LAN only powers or wakes the physical host; it does not start League, authenticate, or prove Vanguard/gameplay.",
			"After the host wakes, verify the physical Windows/macOS session and use the separate remote pair/list/stream or KVM flow.",
			"The packet is sent without authentication; restrict the destination to a trusted LAN or private network.",
		},
		validated:      true,
		mac:            mac,
		destination:    destination,
		port:           request.Port,
		packet:         append([]byte(nil), packet...),
		packetBinding:  append([]byte(nil), packet...),
		requestBinding: requestBinding{mac: mac, destination: destination, port: request.Port},
	}, nil
}

func magicPacket(mac string) []byte {
	address, _ := net.ParseMAC(mac)
	packet := make([]byte, magicPacketSize)
	for index := 0; index < 6; index++ {
		packet[index] = 0xff
	}
	for repeat := 0; repeat < 16; repeat++ {
		copy(packet[6+repeat*6:], address)
	}
	return packet
}

func packetMatches(left, right []byte) bool {
	return bytes.Equal(left, right)
}

// Execute is the only network boundary for this helper. The socket enables
// IPv4 broadcast explicitly and honours cancellation/deadlines from ctx.
func Execute(ctx context.Context, plan Plan) error {
	if !plan.validated {
		return errors.New("refusing to execute an unvalidated Wake-on-LAN plan; construct it with BuildPlan")
	}
	mac, err := NormalizeMAC(plan.MAC)
	if err != nil || mac != plan.requestBinding.mac || mac != plan.mac {
		return errors.New("refusing to execute a Wake-on-LAN plan whose MAC changed after planning")
	}
	destination, err := NormalizeDestination(plan.Destination)
	if err != nil || destination != plan.requestBinding.destination || destination != plan.destination {
		return errors.New("refusing to execute a Wake-on-LAN plan whose destination changed after planning")
	}
	if plan.Port != plan.requestBinding.port || plan.Port != plan.port || plan.Port < 1 || plan.Port > 65535 {
		return errors.New("refusing to execute a Wake-on-LAN plan whose port changed after planning")
	}
	expected := magicPacket(mac)
	if !packetMatches(plan.packet, plan.packetBinding) || !packetMatches(plan.packet, expected) {
		return errors.New("refusing to execute a Wake-on-LAN plan whose packet changed after planning")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("refusing to execute a canceled Wake-on-LAN handoff: %w", err)
	}

	dialer := net.Dialer{Control: enableBroadcast}
	connection, err := dialer.DialContext(ctx, "udp4", net.JoinHostPort(destination, strconv.Itoa(plan.Port)))
	if err != nil {
		return fmt.Errorf("open Wake-on-LAN socket: %w", err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := connection.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("set Wake-on-LAN deadline: %w", err)
		}
	}
	written, err := connection.Write(plan.packet)
	if err != nil {
		return fmt.Errorf("send Wake-on-LAN packet: %w", err)
	}
	if written != len(plan.packet) {
		return fmt.Errorf("send Wake-on-LAN packet: wrote %d of %d bytes", written, len(plan.packet))
	}
	return nil
}

// enableBroadcast is split by target OS because syscall.SetsockoptInt uses a
// platform-specific descriptor type on Windows while Linux/BSD use int.
func enableBroadcast(network, address string, raw syscall.RawConn) error {
	return setBroadcastSocket(raw)
}
