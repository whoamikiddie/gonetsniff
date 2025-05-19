package fingerprint

// DeviceSignature represents a device signature
type DeviceSignature struct {
	Category    string            // General category (PC, Mobile, IoT, etc.)
	Type        string            // Specific type (Smartphone, Smart TV, etc.)
	Vendor      string            // Device manufacturer
	Model       string            // Device model (if known)
	Ports       map[int]string    // Common ports and their services
	Protocols   []string          // Common protocols used
	DHCPVendor  []string         // DHCP vendor strings
	UserAgents  []string         // Common User-Agent patterns
	MACPrefixes []string         // MAC address prefixes (OUI)
	Services    map[string]string // Common services and their versions
}

var deviceSignatures = map[string]DeviceSignature{
	"smartphone": {
		Category: "Mobile",
		Type:     "Smartphone",
		Ports: map[int]string{
			62078: "Apple iPhone Sync",
			5228:  "Android Push Notifications",
		},
		Protocols: []string{"mDNS", "SSDP", "DHCP", "DNS", "HTTP", "HTTPS"},
		DHCPVendor: []string{
			"iPhone",
			"Android",
			"samsung-android",
			"huawei-android",
			"xiaomi-android",
		},
		UserAgents: []string{
			"iPhone",
			"Android",
			"Mobile",
			"Samsung",
			"Huawei",
			"Xiaomi",
		},
	},
	"smart_tv": {
		Category: "IoT",
		Type:     "Smart TV",
		Ports: map[int]string{
			3000:  "Roku",
			7000:  "Samsung TV",
			8001:  "Samsung TV Web",
			8008:  "Google Cast",
			8009:  "Google Cast",
			55000: "LG webOS",
		},
		Protocols: []string{"SSDP", "DLNA", "HDCP", "DIAL"},
		DHCPVendor: []string{
			"Roku",
			"SamsungTV",
			"LGwebOS",
			"Sony-TV",
			"Vizio-TV",
		},
	},
	"gaming_console": {
		Category: "Gaming",
		Type:     "Console",
		Ports: map[int]string{
			3074:  "Xbox Live",
			3075:  "Xbox Live",
			3658:  "PlayStation Network",
			3659:  "PlayStation Network",
			27015: "Steam",
			27036: "Steam",
		},
		Protocols: []string{"PSN", "Xbox Live", "Nintendo Online"},
		DHCPVendor: []string{
			"Xbox",
			"PlayStation",
			"Nintendo",
		},
	},
	"iot_camera": {
		Category: "IoT",
		Type:     "Security Camera",
		Ports: map[int]string{
			554:  "RTSP",
			80:   "HTTP",
			443:  "HTTPS",
			8000: "HTTP Alt",
			8554: "RTSP Alt",
		},
		Protocols: []string{"RTSP", "ONVIF", "RTP", "RTCP"},
		DHCPVendor: []string{
			"Hikvision",
			"Dahua",
			"Axis",
			"Nest-Cam",
			"Ring-Cam",
		},
	},
	"smart_speaker": {
		Category: "IoT",
		Type:     "Smart Speaker",
		Ports: map[int]string{
			8009: "Google Cast",
			4070: "Amazon Echo",
			5353: "mDNS",
		},
		Protocols: []string{"mDNS", "SSDP", "AirPlay"},
		DHCPVendor: []string{
			"Echo",
			"Google-Home",
			"HomePod",
			"Sonos",
		},
	},
	"router": {
		Category: "Network",
		Type:     "Router",
		Ports: map[int]string{
			80:   "HTTP",
			443:  "HTTPS",
			22:   "SSH",
			23:   "Telnet",
			53:   "DNS",
			67:   "DHCP",
			68:   "DHCP",
			161:  "SNMP",
			1900: "SSDP",
		},
		Protocols: []string{"DHCP", "DNS", "SNMP", "UPnP"},
		DHCPVendor: []string{
			"Cisco",
			"NETGEAR",
			"TP-LINK",
			"ASUS",
			"D-Link",
			"Ubiquiti",
		},
	},
}

// Common MAC address prefixes (OUI) for major vendors
var macVendors = map[string]string{
	"00:00:0C": "Cisco",
	"00:1A:11": "Google",
	"00:17:88": "Philips",
	"B8:27:EB": "Raspberry Pi",
	"00:11:32": "Synology",
	"F0:9F:C2": "Ubiquiti",
	"00:04:4B": "NVIDIA",
	"00:24:E4": "Withings",
	"74:C2:46": "Amazon",
	"00:17:AB": "Nintendo",
	"70:56:81": "Apple",
	"28:39:26": "Sony",
	"00:26:5A": "D-Link",
	"00:18:4D": "Netgear",
}

// IoT device categories and their common characteristics
var iotCategories = map[string][]string{
	"smart_home": {
		"thermostat",
		"light_bulb",
		"smart_plug",
		"door_lock",
		"garage_door",
		"doorbell",
		"security_system",
	},
	"entertainment": {
		"smart_tv",
		"streaming_device",
		"smart_speaker",
		"media_player",
	},
	"appliances": {
		"refrigerator",
		"washer",
		"dryer",
		"dishwasher",
		"oven",
		"microwave",
	},
	"security": {
		"camera",
		"motion_sensor",
		"smoke_detector",
		"co_detector",
		"water_leak_sensor",
	},
}

// Protocol signatures for different types of devices
var protocolSignatures = map[string][]string{
	"streaming_device": {"DIAL", "DLNA", "HLS", "DASH", "RTSP"},
	"smart_home":      {"MQTT", "ZigBee", "Z-Wave", "Thread"},
	"security":        {"ONVIF", "RTSP", "RTP", "SRTP"},
	"gaming":          {"PSN", "Xbox Live", "Nintendo Online", "Steam"},
	"mobile":          {"QUIC", "HTTP/2", "MQTT", "XMPP"},
}

// Service port ranges for different device types
var servicePortRanges = map[string][]int{
	"IoT":         {80, 443, 1883, 5683, 5684, 8883},
	"Media":       {554, 1935, 7000, 8008, 8009},
	"Gaming":      {3074, 3075, 3658, 3659, 27015, 27036},
	"Mobile":      {5228, 5223, 5242, 62078},
	"Network":     {22, 23, 53, 67, 68, 80, 443, 161, 1900},
	"Smart Home":  {80, 443, 1883, 8883, 8080},
	"Enterprise":  {389, 636, 445, 88, 464},
	"Industrial":  {102, 502, 20000, 44818},
}
