package broadlink

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"time"
)

// Wifi security code for SetupDeviceWifi()
type WifiSecurity int

const (
	WIFI_SECURITY_NONE WifiSecurity = iota
	WIFI_SECURITY_WEP
	WIFI_SECURITY_WPA1
	WIFI_SECURITY_WPA2
	WIFI_SECURITY_WPA_CCMP // WPA1/2 CCMP
	WIFI_SECURITY_5_UNKNOWN
	WIFI_SECURITY_WPA_TKIP // WPA1/2 TKIP
)

var (
	// Port number of broadlink device
	BroadLinkDevicePort = 80
)

// Searches for BroadLink devices can be reached from given localaddr.
// The function always waits listentime if no error occurs.
// When localaddr.Port is 0, a random port will be used.
func DiscoverDevicesFromAddr(listentime time.Duration, localaddr *net.UDPAddr) (devlist []Device, err error) {

	if localaddr == nil {
		err = fmt.Errorf("localaddr cannot be nil")
		return
	}

	deadline := time.Now().Add(listentime)

	// create a UDP listener
	udpconn, err := net.ListenUDP("udp", localaddr)
	if err != nil {
		return
	}
	defer func() {
		e := udpconn.Close()
		if err == nil {
			err = e
		}
	}()
	boundaddr := udpconn.LocalAddr().(*net.UDPAddr)

	// build broadcast packet
	// BroadLink UDP packets are QUIC specfication

	packet := make([]byte, 0x30)

	t := time.Now()
	_, tz := t.Zone()
	tz /= 3600 // convert to hour-scale timezone.
	//	tz -= 1
	binary.LittleEndian.PutUint32(packet[0x08:], uint32(tz))
	binary.LittleEndian.PutUint16(packet[0x0c:], uint16(t.Year()))
	packet[0x0e] = byte(t.Second())
	packet[0x0f] = byte(t.Minute())
	packet[0x10] = byte(t.Hour())
	packet[0x11] = byte(t.Weekday())
	packet[0x12] = byte(t.Day())
	packet[0x13] = byte(t.Month())

	// source address/port
	ip := boundaddr.IP.To4()
	packet[0x18], packet[0x19], packet[0x1a], packet[0x1b] = ip[3], ip[2], ip[1], ip[0] // in reverse order
	binary.LittleEndian.PutUint16(packet[0x1c:], uint16(boundaddr.Port))

	// Command byte
	packet[0x26] = 0x06 // 0x06: Hello

	// checksum
	sum := checksum(packet)
	binary.LittleEndian.PutUint16(packet[0x20:], sum)

	// Send broadcast packet
	err = udpconn.SetDeadline(deadline)
	if err != nil {
		return
	}
	broadcastAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: BroadLinkDevicePort}
	_, err = udpconn.WriteTo(packet, broadcastAddr)
	if err != nil {
		return
	}
	// printhex(packet)

	// wait for response
	devlist = make([]Device, 0)
	resp := make([]byte, 2048)
	for {
		sz, raddr, e := udpconn.ReadFromUDP(resp)
		if ope, ok := e.(*net.OpError); ok {
			if ope.Timeout() {
				// deadline passed
				return
			}
		}
		if e != nil {
			err = e
			return
		}
		if sz == 0 {
			continue
		}
		r := resp[:sz]
		// printhex(r)

		// validate received packet
		if !packetChecksumOK(r) {
			continue
		}
		if r[0x26] != 0x07 { // command byte is not a Hello response
			continue
		}

		// read device info
		var newdev Device

		newdev.Type = uint16(r[0x35])<<8 | uint16(r[0x34])

		newdev.UDPAddr = *raddr
		ip := net.IPv4(r[0x39], r[0x38], r[0x37], r[0x36]) // remote addr must be same with r[0x36:0x3a]
		if bytes.Compare(newdev.UDPAddr.IP.To4(), ip.To4()) != 0 {
			// ip address forged
			continue
		}

		// 0x3a - 0x3f : MAC addres in reverse order
		newdev.MACAddr = make([]byte, 6)
		for i := 0; i < 6; i++ {
			newdev.MACAddr[5-i] = r[0x3a+i]
		}

		/*
			// Device kind name
			// RM Blackbean: "智能遥控"
			var n int
			for n = 0x40; n < sz; n++ {
				if r[n] == 0 {
					break
				}
			}
			deviceKind := string(r[0x40:n])
		*/

		// store local address
		newdev.LocalAddr = *localaddr
		// newdev.LocalAddr = *boundaddr

		devlist = append(devlist, newdev)
	}

	return
}

// Try to discover all reachable BroadLink devices.
// The function waits listentime for reply from devices.
// listenport is a UDP port number to be listened on. If listenport is zero, a port number will be chosen automatically. Be sure the port is not blocked by firewalls.
func DiscoverDevices(listentime time.Duration, listenUDPPort int) (devlist []Device, err error) {

	if listentime <= 0 {
		err = fmt.Errorf("a positive listentime duration must be given")
		return
	}
	// list up local IPv4 addresses
	ipv4s, err := ipV4Addrs()
	if err != nil {
		return
	}

	ch := make(chan []Device)
	devlist = make([]Device, 0)

	var wg, wgdone sync.WaitGroup

	// result collector
	wgdone.Add(1)
	go func() {
		defer wgdone.Done()
		for {
			d, ok := <-ch
			if !ok {
				return
			}
			devlist = append(devlist, d...)
		}
	}()

	// Execute discover function over available IPv4 addresses.
	for _, a := range ipv4s {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()

			laddr := &net.UDPAddr{IP: ip, Port: listenUDPPort}
			found, e := DiscoverDevicesFromAddr(listentime, laddr)
			if e != nil {
				err = e
				return
			}
			ch <- found
		}(a)
	}
	wg.Wait()
	close(ch)
	wgdone.Wait()

	return
}

// Try to set up a wifi connection of BroadLink device by broadcasting wifi password over UDP network.
// ssid, password parameter pair is WIFI name and password. wifiSecurity is type of WIFI security. Should be a WIFI_SECURITY_xxxx values.
// localaddr will be directly passed to net.ListenUDP(), which means; If the IP field of laddr is nil or an unspecified IP address, ListenUDP listens on all available IP addresses of the local system except multicast IP addresses. If the Port field of laddr is 0, a port number is automatically chosen.
func SetupDeviceWifi(ssid, password string, security WifiSecurity, localaddr *net.UDPAddr) (err error) {

	// build packet
	packet := make([]byte, 0x88)

	packet[0x26] = 0x14 // command

	if len(ssid) > 0x1f { // WIFI ssid
		ssid = ssid[:0x1f]
	}
	copy(packet[0x44:], ssid)
	packet[0x84] = byte(len(ssid))

	if len(password) > 0x1f { // WIFI password
		password = password[:0x1f]
	}
	copy(packet[0x64:], password)
	packet[0x85] = byte(len(password))

	packet[0x86] = byte(security) // security mode

	// Write packet
	udpconn, err := net.ListenUDP("udp", localaddr)
	if err != nil {
		return
	}
	defer func() {
		e := udpconn.Close()
		if err == nil {
			err = e
		}
	}()
	broadcastAddr := &net.UDPAddr{IP: net.IPv4bcast, Port: BroadLinkDevicePort}
	_, err = udpconn.WriteTo(packet, broadcastAddr)
	if err != nil {
		return
	}

	return
}

// Get all IPv4 addresses available in the system.
func ipV4Addrs() (ipv4addr []net.IP, err error) {
	ifi, err := net.Interfaces()
	if err != nil {
		return
	}

	for _, d := range ifi {
		addr, e := d.Addrs()
		if e != nil {
			err = e
			return
		}
		for _, a := range addr {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ipv4 := ipnet.IP.To4()
			if ipv4 == nil {
				continue
			}

			if ipv4addr == nil {
				ipv4addr = make([]net.IP, 0)
			}
			ipv4addr = append(ipv4addr, ipv4)
		}
	}
	return
}
