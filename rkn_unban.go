package main

import (
	"fmt"
	"github.com/joeshaw/envdecode"
	"log"
	"net"
)

func main() {
	cfg := Config{}
	if err := envdecode.StrictDecode(&cfg); err != nil {
		log.Fatal(err)
	}

	err := cfg.Scaleway.initScalewayAPI()
	if err != nil {
		log.Fatal(err)
	}
	ip, err := cfg.Scaleway.getServerIp()
	if err != nil {
		log.Fatal(err)
	}

	blocked, err := getBlockedIpList(cfg.RknDumpUrl.String())
	if err != nil {
		log.Fatal(err)
	}

	if isBlocked(blocked, net.ParseIP(ip.Address)) {
		newIP, err := cfg.Scaleway.getUnblockedIp(blocked)
		if err != nil {
			log.Fatal(err)
		}
		err = cfg.Scaleway.changeServerIp(ip, newIP)
		if err != nil {
			log.Fatal(err)
		}

		cfg.Cloudflare.initCloudflareClient()
		err = cfg.Cloudflare.updateDnsRecord(newIP.Address)
		if err != nil {
			log.Fatal(err)
		}

		err = cfg.Mikrotik.changeMikrotikIpsecPeer(ip.Address, newIP.Address)
		if err != nil {
			log.Fatal(err)
		}

		err = cfg.SSH.changeLinuxIpsecPeer(ip.Address, newIP.Address)
		if err != nil {
			log.Fatal(err)
		}

		err = checkConnectivity(cfg.SSH.Address)
		if err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Printf("Current IP [%v] is not found in banned IP list. Exiting script.\n", ip.Address)
	}
}
