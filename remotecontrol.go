package broadlink

import (
	"encoding/binary"
	"fmt"
)

// Type of remote controller signal for SendRemoteControlCode().
type RemoteType int

const (
	REMOTE_IR       RemoteType = 0x26 // Infra-Red remote
	REMOTE_RF433Mhz RemoteType = 0xb2 // RF remote of 433Mhz band
	REMOTE_RF315Mhz RemoteType = 0xd7 // RF remote of 315Mhz band
)

var (
	ErrNotCaptured = fmt.Errorf("signal not captured") // Remote controller signal not captured (yet)
)

// Set the device to enter IR/RF remote controller signal capture mode.
func (d *Device) StartCaptureRemoteControlCode() (err error) {

	packet := make([]byte, 0x10)

	packet[0] = 0x03 // sub-command 0x03: start capture a remote control code

	res, err := d.Call(0x6a, packet)
	if err != nil {
		return
	}
	rescode := binary.LittleEndian.Uint16(res[0x22:0x24])
	if rescode != 0 {
		err = fmt.Errorf("failed to start capturing remote control code")
	}
	return
}

// Read captured remote control code. The device must be in signal capture mode to capture a signal. If no signal is captured, this function returns err = ErrNotCaptured. if err is nil, rtype and code will have captured data.
func (d *Device) ReadCapturedRemoteControlCode() (rtype RemoteType, code []byte, err error) {

	packet := make([]byte, 0x10)
	packet[0] = 0x04 // sub-command 0x04: read captured control code

	res, err := d.Call(0x6a, packet)
	if err != nil {
		return
	}
	rescode := binary.LittleEndian.Uint16(res[0x22:0x24])
	if rescode != 0 {
		if rescode == 0xfff6 {
			err = ErrNotCaptured
		} else {
			err = fmt.Errorf("failed reading remote control code")
		}
		return
	}

	data, err := d.getPayload(res)
	if err != nil {
		return
	}
	if len(data) < 8 {
		err = fmt.Errorf("incomplete data")
		return
	}

	cmd := binary.LittleEndian.Uint16(data[:4])
	if cmd != 0x04 {
		err = fmt.Errorf("invalid command code")
		return
	}

	rtype = RemoteType(data[4]) // signal type

	sz := int(RemoteType(binary.LittleEndian.Uint16(data[6:8])))
	if len(data) < 8+sz {
		err = fmt.Errorf("incomplete data")
		return
	}
	code = data[8 : 8+sz]

	return
}

// Send out a remote control code.
// rtype is remote controller signal type. code is some byte stream captured by ReadCapturedRemoteControlCode(). count is repeat count. 1 for once, 2 for twice, ...
func (d *Device) SendRemoteControlCode(rtype RemoteType, code []byte, count int) (err error) {
	packet := make([]byte, 0x08+len(code))

	packet[0] = 0x02 // subcommand 0x02: send a remote control code

	packet[4] = byte(rtype) // 0x26 = IR, 0xb2 for RF 433Mhz, 0xd7 for RF 315Mhz

	// repeat count is zero-based: 0 for once, 1 for twice, ...
	count--
	if count < 0 {
		err = fmt.Errorf("count must be a positive integer")
		return
	}
	packet[5] = byte(count)

	binary.LittleEndian.PutUint16(packet[6:], uint16(len(code))) // code length
	copy(packet[8:], code)                                       // code bytes

	res, err := d.Call(0x6a, packet)
	if err != nil {
		return
	}

	rescode := binary.LittleEndian.Uint16(res[0x22:0x24])
	if rescode != 0 {
		err = fmt.Errorf("failed sending remote control code (%04x)", rescode)
		return
	}

	return
}

// Send out a IR remote code. Same function with calling SendRemoteControlCode() with rtype=REMOTE_IR.
func (d *Device) SendIRRemoteCode(code []byte, count int) (err error) {
	return d.SendRemoteControlCode(REMOTE_IR, code, count)
}
