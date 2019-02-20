package main

import (
	"github.com/crackcomm/cloudflare"
	"github.com/scaleway/go-scaleway"
	"net/url"
)

type ScalewayConfig struct {
	API *api.ScalewayAPI
	Organization string	`env:"SCW_ORGANIZATION,required"`
	Token string		`env:"SCW_TOKEN,required"`
	Region string		`env:"SCW_REGION,default=ams1"`
	ServerName string   `env:"SCW_SERVER_NAME,required"`
	UserAgent string    `env:"USER_AGENT,default=go-scaleway"`
}

type TelegramConfig struct {
	BotToken string     `env:"TELEGRAM_BOT_TOKEN"`
	Debug bool          `env:"TELEGRAM_DEBUG,default=true"`
	RefreshInterval int `env:"TELEGRAM_REFRESH_INTERVAL,default=60"`
}

type CloudflareConfig struct {
	Client *cloudflare.Client
	Email string        `env:"CLOUDFLARE_EMAIL,required"`
	Key string        	`env:"CLOUDFLARE_KEY,required"`
	Zone string       	`env:"CLOUDFLARE_ZONE,required"`
	Domain string       `env:"CLOUDFLARE_DOMAIN,required"`
}

type MikrotikConfig struct {
	Address string    	`env:"ROS_ADDRESS,required"`
	Port int    		`env:"ROS_PORT,default=8728"`
	Username string    	`env:"ROS_USERNAME,required"`
	Password string    	`env:"ROS_PASSWORD,required"`
}

type SSHConfig struct {
	Address string      `env:"SSH_ADDRESS,required"`
	Port int           	`env:"SSH_PORT,default=22"`
	Username  string   	`env:"SSH_USERNAME,required"`
	PublicKey string   	`env:"SSH_PUBLIC_KEY,required"`
}

type Config struct {
	Scaleway ScalewayConfig
	Telegram TelegramConfig
	Cloudflare CloudflareConfig
	Mikrotik MikrotikConfig
	SSH SSHConfig

	RknDumpUrl *url.URL	`env:"RKN_DUMP_URL,required"`
}
