package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	// You need to hardcode device name or make a selection
	iFaceName         = "\\Device\\NPF_{6B2937AF-EEB3-4F0C-AF94-2EEF0E9D14BB}"
	snapshotLen int32 = 1024
	promiscuous bool  = false
	err         error
	timeout     time.Duration = -1 * time.Second
	handle      *pcap.Handle
	packetCount int = 0

	IFMap = make(map[int]pcap.Interface, 0)
)

/*

	194.187.19.129 - AUTH

	00000000  02 04 00 07 01 00 75 27 0d 00 5b 44 45 5d 20 4c  |......u'..[DE] L|
	00000010  61 6b 61 73 68 69 6e 0e 00 31 39 34 2e 31 38 37  |akashin..194.187|
	00000020  2e 31 39 2e 31 33 30 01 00 00 00 b4 02 00 00 01  |.19.130.........|
	00000030  02 00 76 27 0d 00 5b 4e 41 5d 20 54 65 6e 65 62  |..v'..[NA] Teneb|
	00000040  72 69 73 0e 00 32 30 36 2e 32 35 33 2e 31 37 35  |ris..206.253.175|
	00000050  2e 33 37 02 00 00 00 dd 05 00 00 00 03 00 77 27  |.37...........w'|
	00000060  0b 00 5b 45 4e 5d 20 43 61 6e 64 75 73 0e 00 31  |..[EN] Candus..1|
	00000070  39 34 2e 31 38 37 2e 31 39 2e 31 33 30 02 00 00  |94.187.19.130...|
	00000080  00 55 07 00 00 00 04 00 78 27 0a 00 5b 46 52 5d  |.U......x'..[FR]|
	00000090  20 52 75 63 63 6f 0e 00 31 39 34 2e 31 38 37 2e  | Rucco..194.187.|
	000000a0  31 39 2e 31 33 30 01 00 00 00 f2 01 00 00 00 05  |19.130..........|
	000000b0  00 79 27 0a 00 5b 50 4c 5d 20 47 72 61 63 65 0e  |.y'..[PL] Grace.|
	000000c0  00 31 39 34 2e 31 38 37 2e 31 39 2e 31 33 30 01  |.194.187.19.130.|
	000000d0  00 00 00 45 01 00 00 00 06 00 7a 27 0e 00 5b 45  |...E......z'..[E|
	000000e0  53 5d 20 41 6d 61 72 79 6c 6c 69 73 0e 00 31 39  |S] Amaryllis..19|
	000000f0  34 2e 31 38 37 2e 31 39 2e 31 33 30 01 00 00 00  |4.187.19.130....|
	00000100  ba 00 00 00 00 07 00 7b 27 0a 00 5b 49 54 5d 20  |.......{'..[IT] |
	00000110  55 72 69 65 6c 0e 00 31 39 34 2e 31 38 37 2e 31  |Uriel..194.187.1|
	00000120  39 2e 31 33 30 01 00 00 00 ae 00 00 00 00 00 00  |9.130...........|
	00000130  00 00 00                                         |...|

	194.187.19.22 - ? (only in tutorial)
	206.253.175.37
	94.187.19.130
*/

func main() {
	fmt.Println("SoulWorker Sniffer - d3vil401 (d3vsite.org)")

	ImportKeyTable("keyTable.d3v")

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Select network interface:")
	var scounter int = 0
	for _, device := range devices {
		fmt.Printf("[%d] [ %s ] | %s | ", scounter, device.Description, device.Name)
		for _, address := range device.Addresses {
			fmt.Printf("%s ", address.IP)
		}
		fmt.Printf("\n")

		IFMap[scounter] = device
		scounter++
	}

	// Open the device for capturing
	handle, err = pcap.OpenLive(iFaceName, snapshotLen, promiscuous, timeout)
	if err != nil {
		fmt.Printf("Error opening device %s: %v", iFaceName, err)
		os.Exit(1)
	}
	defer handle.Close()

	var filter string = "tcp and net 194.187.19.0/24 or net 206.253.175.37 or net 94.187.19.130"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	// Start processing packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}
}

var (
	keyTable = make([]byte, 0)
)

func ImportKeyTable(path string) error {
	if len(path) > 1 {
		if buffer, err := ioutil.ReadFile(path); err != nil {
			return err
		} else {
			keyTable = buffer
			return nil
		}
	}

	return errors.New("EmptyPath")
}

func Decrypt(buffer []byte) []byte {
	if len(buffer) > 4 && len(keyTable) > 1 {
		var keyIdentifier uint8
		var size uint16
		var encryptedBuffer []byte
		var sender uint8

		reader := bytes.NewReader(buffer)
		binary.Read(reader, binary.LittleEndian, &keyIdentifier)
		binary.Read(reader, binary.LittleEndian, &size)
		binary.Read(reader, binary.LittleEndian, &sender)
		encryptedBuffer = buffer[5:len(buffer)]
		outBuff := make([]byte, len(buffer))

		copy(outBuff[0:5], buffer[0:5])
		for i := uint16(0); i < uint16(len(encryptedBuffer)); i++ {
			// KeyIdentifier is always 2, if it's too big and gets out of range then it's not a packet we recognize from the sw protocol.
			if int(4*uint16(keyIdentifier)-3*(i/3)+i) > len(keyTable) {
				return buffer
			}
			outBuff[5+i] = encryptedBuffer[i] ^ keyTable[4*uint16(keyIdentifier)-3*(i/3)+i]
		}

		return outBuff
	}
	return nil
}

func processPacket(pack gopacket.Packet) {
	ipLayer := pack.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)

		tcpLayer := pack.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			applicationLayer := pack.ApplicationLayer()
			if applicationLayer != nil {
				fmt.Printf("[ %s:%d -> %s:%d ]\n%s\n", ip.SrcIP, tcp.SrcPort, ip.DstIP, tcp.DstPort, hex.Dump(Decrypt(applicationLayer.Payload())))

			}
		}

	}
}
