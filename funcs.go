package main

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	csvDelimiter = rune(';')
	protocolICMP = 1
)

func isBlocked(blocked *[]net.IP, ip net.IP) bool {
	for _, a := range *blocked {
		if ip.Equal(a) {
			return true
		}
	}
	return false
}

func getBlockedIpList(url string) (*[]net.IP, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	list, err := parseIpList(bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	fmt.Printf("Successfully parsed banned IP list for a total of %v IPs\n", len(*list))
	return list, nil
}

func parseIpList(reader io.Reader) (*[]net.IP, error) {
	csvReader := csv.NewReader(reader)
	csvReader.Comma = csvDelimiter
	// fixes unexpected number of fields error
	csvReader.FieldsPerRecord = -1

	// skip header
	csvReader.Read()

	list := make([]net.IP, 0)
	for {
		record, err := csvReader.Read()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, err
		}

		if strings.ContainsRune(record[0], '|') {
			for _, v := range strings.Split(record[0], "|") {
				if ip := net.ParseIP(strings.TrimSpace(v)); ip != nil {
					list = append(list, ip)
				}
			}
		} else {
			if ip := net.ParseIP(record[0]); ip != nil {
				list = append(list, ip)
			}
		}
	}
	return &list, nil
}

func sendIcmpRequest(ip string) error {
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return err
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("1234567890"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}
	if _, err := c.WriteTo(wb, &net.UDPAddr{IP: net.ParseIP(ip)}); err != nil {
		return err
	}

	rb := make([]byte, 1500)
	n, peer, err := c.ReadFrom(rb)
	if err != nil {
		return err
	}
	rm, err := icmp.ParseMessage(protocolICMP, rb[:n])
	if err != nil {
		return err
	}
	if rm.Type == ipv4.ICMPTypeEchoReply && strings.Split(peer.String(), ":")[0] == ip {
		return nil
	}
	return errors.New(fmt.Sprintf("icmp request [%v]: failed to get ICMPEchoReply", ip))
}

func checkConnectivity(ip string) error {
	timeout := time.After(15 * time.Second)
	ticker := time.Tick(1 * time.Second)

	for {
		select {
		case <-timeout:
			return errors.New(fmt.Sprintf("connectivity check [%v]: timeout exceeded", ip))
		case <-ticker:
			if err := sendIcmpRequest(ip); err == nil {
				return nil
			}
		}
	}
}
