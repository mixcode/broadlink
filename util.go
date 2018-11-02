package broadlink

import (
	"fmt"
)

// Broadlink byte checksum
func checksum(data []byte) (sum uint16) {
	sum = 0xbeaf
	for _, b := range data {
		sum += uint16(b)
	}
	return
}

// verify checksum of a packet
func packetChecksumOK(packet []byte) bool {

	if len(packet) < 0x22 {
		return false
	}

	// checksum in data packet
	packetsum := uint16(packet[0x21])<<8 | uint16(packet[0x20])

	// calculated checksum
	sum := checksum(packet)
	sum -= uint16(packet[0x20]) // remove checksum value bytes
	sum -= uint16(packet[0x21])

	return sum == packetsum
}

func printhex(data []byte) {
	fmt.Printf(">00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f\n -----------------------------------------------\n ")
	i := 0
	for _, b := range data {
		fmt.Printf("%02x", b)
		i++
		switch i {
		case 8:
			fmt.Printf(",")
		case 16:
			fmt.Printf("\n ")
			i = 0
		default:
			fmt.Printf(" ")
		}
	}
	if i != 0 {
		fmt.Println()
	}
	fmt.Println()
}
