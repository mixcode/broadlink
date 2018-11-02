package broadlink

var (
	broadlinkDeviceList = map[int][2]string{
		// typecode: { name, class }
		0:      {"SP1", "SP1"},
		0x2711: {"SP2", "SP2"},
		0x2712: {"RM2", "RM"},
		0x2714: {"A1", "A1"},
		0x2719: {"Honeywell SP2", "SP2"},
		0x271a: {"Honeywell SP2", "SP2"},
		0x2720: {"SPMini", "SP2"},
		0x2722: {"SmartOne Alarm Kit", "S1C"},
		0x2728: {"SPMini2", "SP2"},
		0x272a: {"RM2 Pro Plus", "RM"},
		0x2733: {"OEM branded SPMini", "SP2"},
		0x2736: {"SPMiniPlus", "SP2"},
		0x273e: {"OEM branded SPMini", "SP2"},
		0x2737: {"RM Mini / RM3 Mini Blackbean", "RM"},
		0x273d: {"RM Pro Phicomm", "RM"},
		0x277c: {"RM2 Home Plus GDT", "RM"},
		0x2783: {"RM2 Home Plus", "RM"},
		0x2787: {"RM2 Pro Plus2", "RM"},
		0x278b: {"RM2 Pro Plus BL", "RM"},
		0x278f: {"RM Mini Shate", "RM"},
		0x2797: {"RM2 Pro Plus HYC", "RM"},
		0x279d: {"RM2 Pro Plus3", "RM"},
		0x27a1: {"RM2 Pro Plus R1", "RM"},
		0x27a6: {"RM2 Pro PP", "RM"},
		0x27a9: {"RM2 Pro Plus_300", "RM"},

		0x4E4D: {"Dooya DT360E", "Dooya"},
		0x4EAD: {"Hysen controller", "HYSEN"},
		0x4EB5: {"MP1", "MP1"},
		0x4EF7: {"Honyar OEM MP1", "MP1"},

		0x753e: {"SP3", "SP2"},
		0x7919: {"Honeywell SP2", "SP2"},
		0x791a: {"Honeywell SP2", "SP2"},
		0x7d00: {"OEM branded SP3", "SP2"},

		0x9479: {"SP3S", "SP2"},
		0x947a: {"SP3S", "SP2"},
	}
)

// Lookup device name using Device.Type from known device list.
func (d *Device) DeviceName() (name, class string) {
	n := int(d.Type)
	if v, ok := broadlinkDeviceList[n]; ok {
		return v[0], v[1]
	}
	if 0x7530 <= n && n <= 0x7918 {
		return "OEM branded SPMini2", "SP2"
	}
	return "", ""
}
