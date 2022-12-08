package main

import (
	"errors"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

var (
	device      string = "eth0"
	snapshotLen int32  = 1024
	promiscuous bool   = false
	err         error
	timeout     time.Duration = 30 * time.Second
	handle      *pcap.Handle
	localIp     string
)

func main() {
	flag.StringVar(&device, "d", "eth0", "device")
	flag.StringVar(&localIp, "ip", getIp(), "ip")

	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer handle.Close()

	//filter := "tcp"
	//err2 := handle.SetBPFFilter(filter)
	//if err2 != nil {
	//	log.Fatal(err2.Error())
	//}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Print("Program started")
	for packet := range packetSource.Packets() {
		//fmt.Println(packet)
		findSSHPacket(packet)
	}
}

func findSSHPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	var ipSrc string
	if ipLayer == nil {
		return
	} else {
		ip := ipLayer.(*layers.IPv4)
		if ip.DstIP.String() != localIp {
			// 如果目标不是本机
			return
		} else {
			ipSrc = ip.SrcIP.String()
		}
	}

	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		if tcp.DstPort != 22 {
			// 如果不是连接ssh的
			return
		}
	} else {
		return
	}

	data := string(tcpLayer.LayerPayload())
	isSSHLogin := strings.HasPrefix(data, "SSH-2.0")
	if isSSHLogin {
		log.Printf("%s trying to connect ssh\n", ipSrc)
	}
}

func getIp() string {
	ip, err := GetInterfaceIpv4Addr(device)
	if err != nil {
		fmt.Println(err)
		os.Exit(0)
	}
	fmt.Printf("local ip is %s", ip)
	return ip
}

func GetInterfaceIpv4Addr(interfaceName string) (addr string, err error) {
	var (
		ief      *net.Interface
		addrs    []net.Addr
		ipv4Addr net.IP
	)
	if ief, err = net.InterfaceByName(interfaceName); err != nil { // get interface
		return
	}
	if addrs, err = ief.Addrs(); err != nil { // get addresses
		return
	}
	for _, addr := range addrs { // get ipv4 address
		if ipv4Addr = addr.(*net.IPNet).IP.To4(); ipv4Addr != nil {
			break
		}
	}
	if ipv4Addr == nil {
		return "", errors.New(fmt.Sprintf("interface %s don't have an ipv4 address\n", interfaceName))
	}
	return ipv4Addr.String(), nil
}
