package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/chifflier/nfqueue-go/nfqueue"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func realCallback(payload *nfqueue.Payload) int {
	// Decode a packet
	packet := gopacket.NewPacket(payload.Data, layers.LayerTypeIPv4, gopacket.Default)
	// Get the TCP layer from this packet
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		// Get actual TCP data from this layer
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From src port %d to dst port %d\n", tcp.SrcPort, tcp.DstPort)
	}
	//Log Initial State
	fmt.Printf("  id: %d\n", payload.Id)
	fmt.Println(hex.Dump(payload.Data))
	if app := packet.ApplicationLayer(); app != nil {
		if strings.Contains(string(app.Payload()), "cloud") {
			// modify payload of application layer
			*packet.ApplicationLayer().(*gopacket.Payload) = bytes.ReplaceAll(app.Payload(), []byte("cloud"), []byte("butt"))

			// if its tcp we need to tell it which network layer is being used
			// to be able to handle multiple protocols we can add a if clause around this
			packet.TransportLayer().(*layers.TCP).SetNetworkLayerForChecksum(packet.NetworkLayer())

			buffer := gopacket.NewSerializeBuffer()
			options := gopacket.SerializeOptions{
				ComputeChecksums: true,
				FixLengths:       true,
			}

			// Serialize Packet to get raw bytes
			if err := gopacket.SerializePacket(buffer, options, packet); err != nil {
				log.Fatalln(err)
			}

			packetBytes := buffer.Bytes()
			//fmt.Printf("  id: %d MODIFIED\n", payload.Id)
			dmp := diffmatchpatch.New()
			diffs := dmp.DiffMain(hex.Dump(payload.Data), hex.Dump(packetBytes), true)
			fmt.Println(dmp.DiffPrettyText(diffs))
			payload.SetVerdictModified(nfqueue.NF_ACCEPT, packetBytes)
			return 0
		}
	}
	fmt.Println("-- ")
	payload.SetVerdict(nfqueue.NF_ACCEPT)
	return 0
}

func main() {
	q := new(nfqueue.Queue)

	q.SetCallback(realCallback)

	q.Init()

	q.Unbind(syscall.AF_INET)
	q.Bind(syscall.AF_INET)

	q.CreateQueue(0)

	cmd := exec.Command("iptables", "-t", "raw", "-A", "PREROUTING", "-p", "tcp", "--source-port", "43594:43595", "-j", "NFQUEUE", "--queue-num", "0")
	stdout, err := cmd.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	} else {
		fmt.Println(string(stdout))
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	log.SetOutput(ioutil.Discard)
	go func() {
		for sig := range c {
			// sig is a ^C, handle it
			_ = sig
			q.StopLoop()
		}
	}()

	// XXX Drop privileges here

	q.Loop()
	q.DestroyQueue()
	q.Close()

	unroute := exec.Command("iptables", "-F")
	stdoutUnroute, err := unroute.Output()

	if err != nil {
		fmt.Println(err.Error())
		return
	} else {
		fmt.Println(string(stdoutUnroute))
	}

	os.Exit(0)
}
