package utils

import (
	"os"

	"github.com/sirupsen/logrus"
)

// InitLogger initializes the logger with appropriate settings
func InitLogger() {
	// Set log format
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	// Set output to stdout
	logrus.SetOutput(os.Stdout)

	// Set log level
	logrus.SetLevel(logrus.InfoLevel)
}

// MAC vendor database (simplified version)
var macVendorDB = map[string]string{
	"00:00:0C": "Cisco Systems",
	"00:01:42": "Cisco Systems",
	"00:03:6B": "Cisco Systems",
	"00:04:0B": "3COM",
	"00:05:02": "Apple",
	"00:0A:27": "Apple",
	"00:0A:95": "Apple",
	"00:0D:93": "Apple",
	"00:11:24": "Apple",
	"00:14:51": "Apple",
	"00:16:CB": "Apple",
	"00:17:F2": "Apple",
	"00:19:E3": "Apple",
	"00:1B:63": "Apple",
	"00:1C:B3": "Apple",
	"00:1D:4F": "Apple",
	"00:1E:52": "Apple",
	"00:1E:C2": "Apple",
	"00:1F:5B": "Apple",
	"00:1F:F3": "Apple",
	"00:21:E9": "Apple",
	"00:22:41": "Apple",
	"00:23:12": "Apple",
	"00:23:32": "Apple",
	"00:23:6C": "Apple",
	"00:23:DF": "Apple",
	"00:25:00": "Apple",
	"00:25:BC": "Apple",
	"00:26:08": "Apple",
	"00:26:BB": "Apple",
	"00:30:65": "Apple",
	"00:50:56": "VMware",
	"00:50:BA": "D-Link",
	"00:80:C8": "D-Link",
	"00:90:4C": "Epson",
	"00:E0:4C": "Realtek",
	"18:E7:F4": "Samsung",
	"20:F4:78": "Xiaomi",
	"28:6C:07": "Xiaomi",
	"34:CE:00": "Xiaomi",
	"38:A4:ED": "Xiaomi",
	"3C:BD:D8": "LG Electronics",
	"40:B0:76": "ASUSTek",
	"44:65:0D": "Amazon",
	"50:C7:BF": "TP-Link",
	"54:60:09": "Google",
	"5C:F3:70": "Huawei",
	"60:38:E0": "Belkin",
	"64:9E:F3": "Cisco Systems",
	"70:56:81": "Apple",
	"74:D4:35": "Gionee",
	"78:32:1B": "Samsung",
	"7C:BB:8A": "Nintendo",
	"84:78:8B": "Sony",
	"88:53:95": "Apple",
	"8C:85:90": "Apple",
	"90:72:40": "Apple",
	"A4:83:E7": "Apple",
	"AC:BC:32": "Apple",
	"B8:27:EB": "Raspberry Pi",
	"C8:2A:14": "Apple",
	"C8:3A:35": "Tenda",
	"D0:37:45": "TP-Link",
	"D8:96:95": "Apple",
	"DC:56:E7": "Apple",
	"E0:5F:45": "Apple",
	"E8:04:62": "Intel",
	"EC:35:86": "Apple",
	"F0:18:98": "Apple",
	"F4:F5:D8": "Google",
	"F8:1E:DF": "Apple",
}

// LookupVendor returns the vendor name for a given MAC address
func LookupVendor(mac string) string {
	if len(mac) < 8 {
		return "Unknown"
	}

	// Extract OUI (first 3 bytes)
	oui := mac[0:8]

	// Look up vendor in database
	if vendor, ok := macVendorDB[oui]; ok {
		return vendor
	}

	return "Unknown"
}
