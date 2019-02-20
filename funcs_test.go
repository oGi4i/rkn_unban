package main

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net"
	"strings"
	"testing"
)

func stringToIpList(list []string) *[]net.IP {
	var ipList []net.IP
	for _, v := range list {
		if ip := net.ParseIP(v); ip != nil {
			ipList = append(ipList, ip)
		}
	}
	return &ipList
}

func TestIsBlocked(t *testing.T) {
	ipList := stringToIpList([]string{"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1"})

	assert.False(t, isBlocked(ipList, net.ParseIP("2.2.2.2")))
	assert.True(t, isBlocked(ipList, net.ParseIP("1.1.1.1")))
}

func TestParseIpList(t *testing.T) {
	csvValid := "0.0.0.0;header2\n1.1.1.1 | 2.2.2.2;\n3.3.3.3;\n4.4.4.4 | 5.5.5.5xxx | 6.6.6.6;test.com"
	expected := stringToIpList([]string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "6.6.6.6"})

	result, err := parseIpList(strings.NewReader(csvValid))
	if err != nil {
		t.Fail()
	}
	assert.Equal(t, result, expected)
}

func TestSendIcmpRequest(t *testing.T) {
	if err := sendIcmpRequest("127.0.0.1"); err != nil {
		t.Fail()
	}

	err := sendIcmpRequest("256.0.0.1")
	if err != nil {
		assert.Error(t, errors.New("write udp 0.0.0.0:0->:0: sendto: no route to host"))
	}
}

func TestCheckConnectivity(t *testing.T) {
	if err := checkConnectivity("127.0.0.1"); err != nil {
		t.Fail()
	}
}