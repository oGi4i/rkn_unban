package main

import (
	"errors"
	"fmt"
	"github.com/crackcomm/cloudflare"
	"github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/scaleway/go-scaleway"
	"github.com/scaleway/go-scaleway/types"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/context"
	"gopkg.in/routeros.v2"
	"io/ioutil"
	"log"
	"net"
	"time"
)

func (scw *ScalewayConfig) initScalewayAPI() error {
	API, err := api.NewScalewayAPI(scw.Organization, scw.Token, scw.UserAgent, scw.Region)
	if err != nil {
		return err
	}
	scw.API = API
	return nil
}

func (scw *ScalewayConfig) getServerIp() (*types.ScalewayIPDefinition, error) {
	ips, err := scw.API.GetIPS()
	if err != nil {
		return &types.ScalewayIPDefinition{}, err
	}

	for _, v := range ips.IPS {
		if v.Server != nil {
			if v.Server.Name == scw.ServerName {
				fmt.Printf("Current IP for server [%v]: %v\n", v.Server.Name, v.Address)
				return &v, nil
			}
		}
	}

	return &types.ScalewayIPDefinition{}, errors.New("error getting server ip")
}

func (scw *ScalewayConfig) getUnblockedIp(blocked *[]net.IP) (*types.ScalewayIPDefinition, error) {
	var newIpCandidate types.ScalewayIPDefinition
	bannedIpCandidates := make([]types.ScalewayIPDefinition, 0)
	for {
		newIp, err := scw.API.NewIP()
		if err != nil {
			return &types.ScalewayIPDefinition{}, err
		}
		newIpCandidate = newIp.IP
		// check if we got an IP that is not already banned
		if !isBlocked(blocked, net.ParseIP(newIpCandidate.Address)) {
			break
		} else {
			bannedIpCandidates = append(bannedIpCandidates, newIpCandidate)
		}
	}

	// cleanup, if we got any IPs that were already banned
	if len(bannedIpCandidates) > 0 {
		for _, ip := range bannedIpCandidates {
			err := scw.API.DeleteIP(ip.ID)
			if err != nil {
				fmt.Printf("%+v\n", err)
			}
		}
	}

	fmt.Printf("Got new clean IP from Scaleway: %v\n", newIpCandidate.Address)
	return &newIpCandidate, nil
}

func (scw *ScalewayConfig) changeServerIp(oldIp *types.ScalewayIPDefinition, newIp *types.ScalewayIPDefinition) error {
	err := scw.API.DetachIP(oldIp.ID)
	if err != nil {
		return err
	}
	fmt.Printf("Successfully detached banned IP [%v] from server [%v]\n", oldIp.Address, oldIp.Server.Name)

	err = scw.API.AttachIP(newIp.ID, oldIp.Server.Identifier)
	if err != nil {
		return err
	}
	fmt.Printf("Successfully attached new clean IP [%v] to server [%v]\n", newIp.Address, oldIp.Server.Name)
	return nil
}

func (cfg *TelegramConfig) informViaTelegram(message string) {
	bot, err := tgbotapi.NewBotAPI(cfg.BotToken)
	if err != nil {
		log.Fatal(err)
	}

	bot.Debug = cfg.Debug

	// TODO: implement sending message via Telegram Bot
}

func (cf *CloudflareConfig) initCloudflareClient() {
	cf.Client = cloudflare.New(&cloudflare.Options{
		Email: cf.Email,
		Key:   cf.Key,
	})
}

func (cf *CloudflareConfig) updateDnsRecord(ip string) error {
	ctx := context.Background()
	ctx, _ = context.WithTimeout(ctx, time.Second*30)

	zones, err := cf.Client.Zones.List(ctx)
	if err != nil {
		return err
	} else if len(zones) == 0 {
		return errors.New("no DNS zones were found")
	}

	for _, zone := range zones {
		if zone.Name == cf.Zone {
			records, err := cf.Client.Records.List(ctx, zone.ID)
			if err != nil {
				return err
			}

			for _, record := range records {
				if record.Name == cf.Domain {
					record.Content = ip

					err := cf.Client.Records.Patch(ctx, record)
					if err != nil {
						return err
					}

					fmt.Printf("Successfully updated DNS record for domain [%v] with IP: %v", cf.Domain, ip)
				}
			}
		}
	}
	return nil
}

func (mt *MikrotikConfig) changeMikrotikIpsecPeer(oldIp string, newIp string) error {
	client, err := routeros.Dial(fmt.Sprintf("%v:%v", mt.Address, mt.Port), mt.Username, mt.Password)
	if err != nil {
		return err
	}

	defer client.Close()

	reply, err := client.Run("/ip/ipsec/peer/print", "?=address="+oldIp+"/32")
	if err != nil {
		return err
	}
	if reply.Re	!= nil {
		peerId := reply.Re[0].Map[".id"]

		reply, err = client.Run("/ip/ipsec/peer/set", "=.id="+peerId, "=address="+newIp+"/32")
		if err != nil {
			return err
		}
	}

	reply, err = client.Run("/ip/ipsec/policy/print", "?=sa-dst-address="+oldIp)
	if err != nil {
		return err
	}
	if reply.Re	!= nil {
		policyId := reply.Re[0].Map[".id"]

		reply, err = client.Run("/ip/ipsec/policy/set", "=.id="+policyId, "=sa-dst-address="+newIp)
		if err != nil {
			return err
		}
	}

	fmt.Printf("Successfully changed IPsec Peer from [%v] to [%v]\n", oldIp, newIp)
	return nil
}

func (sshConfig *SSHConfig) prepareSigner() (*ssh.Signer, error) {
	key, err := ioutil.ReadFile(sshConfig.PublicKey)
	if err != nil {
		return nil, err
	}

	// create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	return &signer, nil
}

func (sshConfig *SSHConfig) changeLinuxIpsecPeer(oldIp string, newIp string) error {
	signer, err := sshConfig.prepareSigner()
	if err != nil {
		return err
	}

	config := &ssh.ClientConfig{
		User: sshConfig.Username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(*signer),
		},
		// TODO: replace with ssh.FixedHostKey(hostKey)
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%v:%v", newIp, sshConfig.Port), config)
	if err != nil {
		return err
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	// update ipsec.conf and restart strongSwan
	err = session.Run(fmt.Sprintf("sed -i 's/leftsourceip=%v/leftsourceip=%v/g' /etc/ipsec.conf && ipsec restart", oldIp, newIp))
	if err != nil {
		return err
	}
	return nil
}
