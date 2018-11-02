# broadlink
A Go package to control BroadLink RM mini 3 "Black Bean" IR remote controller.


### Disclaimer
I built this package just to control my own home appliances, and the RM mini 3 is the only device I have. For other devices, you can fork and implement yourselves. :p


### Code Sample

#### Detect all reachable BroadLink devices 
```golang
devs, err := broadlink.DiscoverDevices(100*time.Millisecond, 0)
fmt.Println(devs)
// d := devs[0]
```

#### Register and auth local machine to detected BroadLink device
```golang
myname := "my test server"  // Your local machine's name.
myid := make([]byte, 15)    // Must be 15 bytes long.
// Fill myid[] with some unique ID for your local machine.

err = d.Auth(myid, myname) // Get my ID and update AES key.
```

#### Capture an IR Remote code
```golang
var ircode []byte

// Enter capturing mode.
err = d.StartCaptureRemoteControlCode()

// Poll captured data.
// Point a remote controller toward the device, and press a button.
ok := false
for i:=0; i<30; i++ {
	ircode, err = d.ReadCapturedRemoteControlCode()
	if err==nil {
		ok = true
		break
	}
	time.Sleep(time.Second)
	continue
}

if ok {
	// ircode now have captured data
}
```

#### Fire an IR code
```golang
err = d.SendIRRemoteCode(ircode, 1)	// 1 means once, 2 is twice, ...
// Note that sending IR signals may take a few hundred milliseconds. Set network timout accordingly.
```


#### Try to connect a New BroadLink device to local Wifi network
```golang
err = broadlink.SetupDeviceWifi("YOUR_WIFI_SSID", "YOUR_WIFI_PASSWORD", broadlink.WIFI_SECURITY_WPA_TKIP, nil)
// try to detect devices below
// devs, err := broadlink.DiscoverDevices(100*time.Millisecond, 0)
```


References
----------

Note that references may have incorrect and inconsistent information.

- mjg59's Python-broadlink tool: https://github.com/mjg59/python-broadlink
- Broadlink smart home devices complete protocol hack: https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1



