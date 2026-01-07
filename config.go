package main

import (
	"regexp"

	"blitiri.com.ar/go/spf"
)

var headersToRemove = []string{"x-*", "x-spam-*", "x-mailer", "x-originating-*", "x-qq-*", "dkim-*", "x-google-*", "x-cm-*", "x-coremail-*", "x-bq-*", "message-id"}
var CONFIG Config

// Pre-compiled regex patterns for better performance
var recipientPattern = regexp.MustCompile(`^(\w|-)+@.+$`)

const headerPrefix = "X-ROUTER-"
const telegramMaxLength = 4096

type Config struct {
	SMTP     SMTPConfig     `yaml:"smtp"`
	Telegram TelegramConfig `yaml:"telegram"`
	Webhook  WebhookConfig  `yaml:"webhook"` // 新增 Webhook 配置
}

type SMTPConfig struct {
	ListenAddress      string   `yaml:"listen_address"`       // Port 25 - SMTP
	ListenAddressTls   string   `yaml:"listen_address_tls"`   // Port 587 - Submission (STARTTLS)
	ListenAddressSmtps string   `yaml:"listen_address_smtps"` // Port 465 - SMTPS (Implicit TLS)
	AllowedDomains     []string `yaml:"allowed_domains"`
	PrivateEmail       string   `yaml:"private_email"`
	CertFile           string   `yaml:"cert_file"`
	KeyFile            string   `yaml:"key_file"`
	EnableDMARC        bool     `yaml:"enable_dmarc"`
	DKIMPrivateKey     string   `yaml:"dkim_private_key"`    // 第一个 DKIM 密钥
	DKIMSelector       string   `yaml:"dkim_selector"`       // 第一个选择器
	DKIMPrivateKey2    string   `yaml:"dkim_private_key_2"`  // 第二个 DKIM 密钥（可选，用于双签名）
	DKIMSelector2      string   `yaml:"dkim_selector_2"`     // 第二个选择器（可选）
	Blacklist          []string `yaml:"blacklist"`           // 黑名单列表（发件人）
	DisabledRecipients []string `yaml:"disabled_recipients"` // 禁用的收件人列表（别名失效）
	MaxMessageBytes    int      `yaml:"max_message_bytes"`
}

type TelegramConfig struct {
	BotToken string `yaml:"bot_token"`
	ChatID   string `yaml:"chat_id"`
	SendEML  bool   `yaml:"send_eml"`
}

type WebhookConfig struct {
	Enabled  bool              `yaml:"enabled"`  // 是否启用 Webhook
	Method   string            `yaml:"method"`   // HTTP 请求方法
	URL      string            `yaml:"url"`      // Webhook URL
	Headers  map[string]string `yaml:"headers"`  // 自定义 Headers
	Body     map[string]string `yaml:"body"`     // 请求体数据（支持模板变量）
	BodyType string            `yaml:"bodyType"` // 请求体类型，可以是 "json" 或 "form"
}

type Backend struct {
}
type Session struct {
	from                 string
	to                   []string
	remoteIP             string
	localIP              string
	spfResult            spf.Result
	remoteclientHostname string
	UUID                 string
	msgId                string
}
