package broadlink

import (
	"fmt"
	"net"
	"testing"
	"time"
)

var (
	_ = net.IPv4len
	_ = fmt.Printf
)

func TestDiscover(t *testing.T) {
	var err error

	// Note: set DiscoverListenPort to set UDP listening port.
	// firewall must be opened for the port to test properly.
	//firewall-cmd --add-port 40001/udp
	listenPort := 40001

	// Setup a device's wifi connection
	//		err = SetupDeviceWifi("SOME_SSID", "WIFI_PASSWORD", WIFI_SECURITY_WPA_TKIP, nil)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	var devs []Device

	/*
		// Single address detectection test
		addrs, err := ipV4Addrs()
		fmt.Println(addrs)
		la := &net.UDPAddr { IP: addrs[1] }
		devs, err = DiscoverDevicesFromAddr(100 * time.Millisecond, la)
		if err!=nil {
			t.Error(err)
		}
		fmt.Println(devs)
	*/

	// Detect all reachable devices
	devs, err = DiscoverDevices(100*time.Millisecond, listenPort)
	if err != nil {
		t.Error(err)
	}
	//fmt.Println(devs)

	if len(devs) > 0 {
		d := devs[0]

		// Print device name
		name, class := d.DeviceName()
		_, _ = name, class
		// fmt.Printf("%x: %s (%s)\n", d.Type, name, class)	// print device info

		// Auth test
		myid := make([]byte, 15)
		for i := 0; i < 15; i++ {
			// Build a test device ID
			myid[i] = byte(i)
		}
		myname := "test server"

		err = d.Auth(myid, myname)
		if err != nil {
			t.Error(err)
		}

		// fmt.Println(d)	// print current device status

		err = d.StartCaptureRemoteControlCode()
		if err != nil {
			t.Error(err)
		}

		remotetype, ircode, err := d.ReadCapturedRemoteControlCode()
		_, _ = remotetype, ircode
		if err != nil && err != ErrNotCaptured {
			t.Error(err)
		}
		if err == nil {
			// fmt.Printf("%x\n", remotetype)
			// printhex(ircode)	// print captured data
		}

	}
}
