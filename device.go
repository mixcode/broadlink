// package broadlink implements functions to control BroadLink RM mini 3 IR-control devices.
package broadlink

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

var (
	defaultTimeout = 500 * time.Millisecond
)

var (
	// packet header bytes for regular communication packet
	regularPacketHeader = []byte{0x5a, 0xa5, 0xaa, 0x55, 0x5a, 0xa5, 0xaa, 0x55}
)

// A Broadlink Device. Information in this structure may updated by device discovery and authorization functions.
// After a device is successfully discovered and authorized, it is safe to store and reuse informations somewhere for later use. Just be sure to store AES encryption key alongside using GetAESKey() and SetAESKey().
type Device struct {
	Type uint16 // Type code of the device

	MACAddr []byte      // MAC address of the device
	UDPAddr net.UDPAddr // IP address of the device

	LocalAddr net.UDPAddr   // Local machine's IP address and port
	Timeout   time.Duration // timeout for a command call

	ID uint32 // Local machine's ID returned on Auth command

	counter uint16 // packet counter

	aesKey   []byte // Key for data encryption
	aesIV    []byte // IV for data encryption
	aesBlock cipher.Block
}

// get timeout duration
func (d *Device) timeout() time.Duration {
	if d.Timeout > 0 {
		return d.Timeout
	}
	return defaultTimeout
}

func (d *Device) buildCmdPacket(cmd byte, payload []byte) (packet []byte) {
	packet = make([]byte, 0x38)

	// Build header
	copy(packet, regularPacketHeader)
	packet[0x24], packet[0x25] = 0x2a, 0x27
	packet[0x26] = cmd
	binary.LittleEndian.PutUint16(packet[0x28:], d.counter) // packet counter
	for i := 0; i < 6; i++ {                                // 0x2a ~ 0x2f : MAC address of the device
		packet[0x2a+i] = d.MACAddr[5-i]
	}
	binary.LittleEndian.PutUint32(packet[0x30:], d.ID) // device ID

	// set payload checksum
	binary.LittleEndian.PutUint16(packet[0x34:], checksum(payload))

	// encrypt payload and attach to header
	encrypted := d.Encrypt(payload)
	packet = append(packet, encrypted...)
	binary.LittleEndian.PutUint16(packet[0x20:], checksum(packet))

	return
}

// Send a command to device and read response.
func (d *Device) Call(cmd byte, payload []byte) (result []byte, err error) {

	if d.MACAddr == nil || len(d.MACAddr) != 6 {
		err = fmt.Errorf("invalid MAC address")
		return
	}

	d.counter++

	packet := d.buildCmdPacket(cmd, payload)

	// printhex(packet)

	//
	// send packet and wait for response
	//

	// create a UDP listener
	deadline := time.Now().Add(d.timeout())
	udpconn, err := net.ListenUDP("udp", &d.LocalAddr)
	if err != nil {
		return
	}
	defer func() {
		e := udpconn.Close()
		if err == nil {
			err = e
		}
	}()
	err = udpconn.SetDeadline(deadline) // set timeout to connection
	if err != nil {
		return
	}

	// send packet and receive response
	_, err = udpconn.WriteTo(packet, &d.UDPAddr)
	if err != nil {
		return
	}
	resp := make([]byte, 2048)
	sz, _, err := udpconn.ReadFromUDP(resp)
	if err != nil {
		return
	}

	result = resp[:sz]

	// verify checksum
	if !packetChecksumOK(result) {
		err = fmt.Errorf("invalid checksum")
		return
	}
	// verify packet counter
	if d.counter != binary.LittleEndian.Uint16(result[0x28:]) {
		err = fmt.Errorf("invalid packet counter")
		return
	}
	// verify MAC address
	for i := 0; i < 6; i++ { // 0x2a ~ 0x2f : MAC address of the device
		if packet[0x2a+i] != d.MACAddr[5-i] {
			err = fmt.Errorf("invalid device mAC ")
			return
		}
	}

	return
}

// Send a command to device but not waits for response.
func (d *Device) Cmd(cmd byte, payload []byte) (result []byte, err error) {

	if d.MACAddr == nil || len(d.MACAddr) != 6 {
		err = fmt.Errorf("invalid MAC address")
		return
	}

	d.counter++
	packet := d.buildCmdPacket(cmd, payload)

	// printhex(packet)

	// create a UDP listener
	deadline := time.Now().Add(d.timeout())
	udpconn, err := net.ListenUDP("udp", &d.LocalAddr)
	if err != nil {
		return
	}
	defer func() {
		e := udpconn.Close()
		if err == nil {
			err = e
		}
	}()
	err = udpconn.SetDeadline(deadline) // set timeout to connection
	if err != nil {
		return
	}

	// send packet
	_, err = udpconn.WriteTo(packet, &d.UDPAddr)
	return
}

// Authorize local machine to remote device.
// localID uniquely identifies local machine to the device.
// The BroadLink device may remember the localID and returns same ID and AES encryption key.
// localName is a human-readable name.
// When succeed, d.ID and d's AES key will be updated.
func (d *Device) Auth(localID []byte, localName string) (err error) {

	if len(localID) != 15 {
		err = fmt.Errorf("local id size must be 15 bytes long")
		return
	}

	// Calculated paded name size
	namelen := len(localName)
	if namelen > 0 {
		namelen--
	}
	namelen = (namelen / 16) * 16

	// calculate payload size
	sz := 0x30 + namelen
	if sz < 0x50 {
		sz = 0x50
	} else if sz > 0x80 {
		sz = 0x80
	}
	payload := make([]byte, sz)

	copy(payload[0x04:0x13], localID)       // local machine's ID
	payload[0x2d] = 0x01                    // delimiter
	copy(payload[0x30:], []byte(localName)) // set the name of my system

	res, err := d.Call(0x65, payload)
	if err != nil {
		return
	}

	/*
		if len(res) <= 0x38 {
			err = fmt.Errorf("blank response")
			return
		}
		data := d.Decrypt(res[0x38:])
	*/
	data, err := d.getPayload(res)
	if err != nil {
		return
	}

	d.SetAESKey(data[0x04:0x14])
	d.ID = binary.LittleEndian.Uint32(data[:0x04])

	return
}

func (d *Device) getPayload(packet []byte) (payload []byte, err error) {
	if len(packet) <= 0x38 {
		err = fmt.Errorf("blank response")
		return
	}
	payload = d.Decrypt(packet[0x38:])
	return
}
