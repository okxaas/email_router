package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"blitiri.com.ar/go/spf"
	"github.com/sirupsen/logrus" // 引入logrus包
	"github.com/yumusb/go-smtp"
)

func main() {
	// 设置logrus为JSON格式
	logrus.SetFormatter(&logrus.JSONFormatter{})
	logrus.SetOutput(os.Stdout)
	logrus.SetLevel(logrus.InfoLevel)

	// 加载配置
	err := LoadConfig("config.yml")
	if err != nil {
		logrus.Fatalf("Error loading config: %v", err)
	}
	// 初始化规则管理器
	if _, err := os.Stat("data"); os.IsNotExist(err) {
		os.Mkdir("data", 0755)
	}
	InitRuleManager("data/rules.json")
	// 输出DMARC配置信息
	if CONFIG.SMTP.EnableDMARC {
		// 检查私钥有效性
		if _, _, pkErr := extractPublicKeyInfo(CONFIG.SMTP.DKIMPrivateKey); pkErr != nil {
			logrus.Errorf("DKIM私钥无效: %v", pkErr)
			logrus.Info("请使用以下命令生成新的DKIM私钥:")
			logrus.Info("openssl genrsa -out dkim_private.pem 2048")
			//logrus.Info("openssl rsa -in dkim_private.pem -pubout -out dkim_public.pem")
			logrus.Info("然后将生成的私钥内容配置到config.yml的DKIMPrivateKey字段中")
			return
		}
		logrus.Infof("DMARC 已启用，使用选择器: %s", CONFIG.SMTP.DKIMSelector)

		// 检查第二个私钥（如果配置）
		if CONFIG.SMTP.DKIMPrivateKey2 != "" {
			if _, _, pkErr := extractPublicKeyInfo(CONFIG.SMTP.DKIMPrivateKey2); pkErr != nil {
				logrus.Errorf("第二个 DKIM 私钥无效: %v", pkErr)
				logrus.Info("请使用以下命令生成新的 Ed25519 DKIM 私钥:")
				logrus.Info("openssl genpkey -algorithm ed25519 -out dkim_private_2.pem")
				return
			}
			logrus.Infof("启用双 DKIM 签名，第二个选择器: %s", CONFIG.SMTP.DKIMSelector2)
		}
	} else {
		logrus.Infof("DMARC 未启用")
	}
	// 推荐的DNS记录 - 使用 fmt 直接输出以保持格式美观
	fmt.Println("")
	fmt.Println("================================================================================")
	fmt.Println("                           推荐的 DNS 记录配置                                  ")
	fmt.Println("================================================================================")
	for _, domain := range CONFIG.SMTP.AllowedDomains {
		fmt.Println("")
		fmt.Printf(">>> 域名: %s\n", domain)
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Println("")
		fmt.Println("[A 记录]")
		fmt.Printf("  名称:  mx.%s\n", domain)
		fmt.Println("  类型:  A")
		fmt.Println("  值:    <您的服务器IP>")
		fmt.Println("")
		fmt.Println("[MX 记录]")
		fmt.Printf("  名称:  %s\n", domain)
		fmt.Println("  类型:  MX")
		fmt.Printf("  值:    5 mx.%s.\n", domain)
		fmt.Println("")
		fmt.Println("[TXT 记录 - SPF]")
		fmt.Printf("  名称:  %s\n", domain)
		fmt.Println("  类型:  TXT")
		fmt.Printf("  值:    v=spf1 mx:%s -all\n", domain)
		if CONFIG.SMTP.EnableDMARC {
			fmt.Println("")
			fmt.Println("[TXT 记录 - DMARC]")
			fmt.Printf("  名称:  _dmarc.%s\n", domain)
			fmt.Println("  类型:  TXT")
			fmt.Printf("  值:    v=DMARC1; p=reject; ruf=mailto:dmarc@%s; fo=1;\n", domain)

			// 第一个 DKIM 记录
			fmt.Println("")
			if CONFIG.SMTP.DKIMPrivateKey2 != "" {
				fmt.Println("[TXT 记录 - DKIM 1]")
			} else {
				fmt.Println("[TXT 记录 - DKIM]")
			}
			fmt.Printf("  名称:  %s._domainkey.%s\n", CONFIG.SMTP.DKIMSelector, domain)
			fmt.Println("  类型:  TXT")
			pubKey, keyType, pkErr := extractPublicKeyInfo(CONFIG.SMTP.DKIMPrivateKey)
			if pkErr != nil {
				logrus.Errorf("获取公钥信息失败: %v", pkErr)
			} else {
				fmt.Printf("  值:    v=DKIM1; k=%s; p=%s\n", keyType, pubKey)
			}

			// 第二个 DKIM 记录（如果配置了双签名）
			if CONFIG.SMTP.DKIMPrivateKey2 != "" && CONFIG.SMTP.DKIMSelector2 != "" {
				fmt.Println("")
				fmt.Println("[TXT 记录 - DKIM 2]")
				fmt.Printf("  名称:  %s._domainkey.%s\n", CONFIG.SMTP.DKIMSelector2, domain)
				fmt.Println("  类型:  TXT")
				pubKey2, keyType2, pkErr2 := extractPublicKeyInfo(CONFIG.SMTP.DKIMPrivateKey2)
				if pkErr2 != nil {
					logrus.Errorf("获取第二个公钥信息失败: %v", pkErr2)
				} else {
					fmt.Printf("  值:    v=DKIM1; k=%s; p=%s\n", keyType2, pubKey2)
				}
			}
		}
		fmt.Println("")
		fmt.Println("--------------------------------------------------------------------------------")
	}
	fmt.Println("")

	logrus.Infof("SMTP 监听地址: %s", CONFIG.SMTP.ListenAddress)
	logrus.Infof("SMTP TLS 监听地址: %s", CONFIG.SMTP.ListenAddressTls)
	logrus.Infof("SMTP 允许的域名: %v", CONFIG.SMTP.AllowedDomains)

	logrus.Infof("Telegram Chat ID: %s", CONFIG.Telegram.ChatID)
	//spf.DNSServer = "1.1.1.1:53"

	be := &Backend{}

	// Setup graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Default MaxMessageBytes to 25MB if not set
	if CONFIG.SMTP.MaxMessageBytes == 0 {
		CONFIG.SMTP.MaxMessageBytes = 25 * 1024 * 1024
	}

	// Plain SMTP server with STARTTLS support
	plainServer := smtp.NewServer(be)
	plainServer.Addr = CONFIG.SMTP.ListenAddress
	plainServer.Domain = GetEnv("MXDOMAIN", "localhost")
	plainServer.WriteTimeout = 10 * time.Second
	plainServer.ReadTimeout = 10 * time.Second
	plainServer.MaxMessageBytes = int64(CONFIG.SMTP.MaxMessageBytes)
	plainServer.MaxRecipients = 50
	plainServer.AllowInsecureAuth = false // Change to true if you want to allow plain auth before STARTTLS (not recommended)

	// Attempt to load TLS configuration for STARTTLS and SMTPS
	cer, err := tls.LoadX509KeyPair(CONFIG.SMTP.CertFile, CONFIG.SMTP.KeyFile)
	if err != nil {
		logrus.Warnf("Loading TLS certificate failed: %v", err)
		logrus.Infof("Starting plainServer only at %s", CONFIG.SMTP.ListenAddress)

		// Start only the plain SMTP server
		go func() {
			if err := plainServer.ListenAndServe(); err != nil {
				logrus.Errorf("Plain server error: %v", err)
			}
		}()

		// Wait for shutdown signal
		<-sigChan
		logrus.Info("Received shutdown signal, gracefully stopping...")
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		if err := plainServer.Shutdown(shutdownCtx); err != nil {
			logrus.Errorf("Error shutting down plain server: %v", err)
		}
		logrus.Info("Server stopped gracefully")
	} else {
		// Certificate loaded successfully, configure STARTTLS
		// Security: Enforce MinVersion TLS 1.2
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cer},
			MinVersion:   tls.VersionTLS12,
		}
		plainServer.TLSConfig = tlsConfig

		// Submission server (port 587) - uses STARTTLS, not implicit TLS
		submissionServer := smtp.NewServer(be)
		submissionServer.Addr = CONFIG.SMTP.ListenAddressTls
		submissionServer.Domain = GetEnv("MXDOMAIN", "localhost")
		submissionServer.WriteTimeout = 10 * time.Second
		submissionServer.ReadTimeout = 10 * time.Second
		submissionServer.MaxMessageBytes = int64(CONFIG.SMTP.MaxMessageBytes)
		submissionServer.MaxRecipients = 50
		submissionServer.AllowInsecureAuth = false
		submissionServer.TLSConfig = tlsConfig

		// SMTPS server (port 465) - uses implicit TLS
		var smtpsServer *smtp.Server
		if CONFIG.SMTP.ListenAddressSmtps != "" {
			smtpsServer = smtp.NewServer(be)
			smtpsServer.Addr = CONFIG.SMTP.ListenAddressSmtps
			smtpsServer.Domain = GetEnv("MXDOMAIN", "localhost")
			smtpsServer.WriteTimeout = 10 * time.Second
			smtpsServer.ReadTimeout = 10 * time.Second
			smtpsServer.MaxMessageBytes = int64(CONFIG.SMTP.MaxMessageBytes)
			smtpsServer.MaxRecipients = 50
			smtpsServer.AllowInsecureAuth = false
			smtpsServer.TLSConfig = tlsConfig
		}

		// Start the plain SMTP server (port 25) with STARTTLS support
		go func() {
			logrus.Infof("Starting SMTP server at %s", CONFIG.SMTP.ListenAddress)
			if err := plainServer.ListenAndServe(); err != nil {
				logrus.Errorf("SMTP server error: %v", err)
			}
		}()

		// Start the Submission server (port 587) with STARTTLS support
		go func() {
			logrus.Infof("Starting Submission server at %s", CONFIG.SMTP.ListenAddressTls)
			if err := submissionServer.ListenAndServe(); err != nil {
				logrus.Errorf("Submission server error: %v", err)
			}
		}()

		// Start the SMTPS server (port 465) with implicit TLS
		if smtpsServer != nil {
			go func() {
				logrus.Infof("Starting SMTPS server at %s", CONFIG.SMTP.ListenAddressSmtps)
				if err := smtpsServer.ListenAndServeTLS(); err != nil {
					logrus.Errorf("SMTPS server error: %v", err)
				}
			}()
		}

		// Wait for shutdown signal
		<-sigChan
		logrus.Info("Received shutdown signal, gracefully stopping...")
		cancel()

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()

		// Shutdown all servers
		if err := plainServer.Shutdown(shutdownCtx); err != nil {
			logrus.Errorf("Error shutting down SMTP server: %v", err)
		}
		if err := submissionServer.Shutdown(shutdownCtx); err != nil {
			logrus.Errorf("Error shutting down Submission server: %v", err)
		}
		if smtpsServer != nil {
			if err := smtpsServer.Shutdown(shutdownCtx); err != nil {
				logrus.Errorf("Error shutting down SMTPS server: %v", err)
			}
		}
		logrus.Info("Servers stopped gracefully")
	}
	_ = ctx // suppress unused variable warning
}
func SPFCheck(s *Session) *smtp.SMTPError {
	remoteHost, _, err := net.SplitHostPort(s.remoteIP)
	if err != nil {
		logrus.Warn("parse remote addr failed")
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 0}, Message: "Invalid remote address"}
	}
	remoteIP := net.ParseIP(remoteHost)
	s.spfResult, err = spf.CheckHostWithSender(remoteIP, s.remoteclientHostname, s.from)
	if err != nil {
		logrus.Warnf("SPF check Result: %v - UUID: %s", err, s.UUID)
		//return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "SPF check failed"}
	}
	logrus.Infof("SPF Result: %v - Domain: %s, Remote IP: %s, Sender: %s - UUID: %s", s.spfResult, getDomainFromEmail(s.from), remoteHost, s.from, s.UUID)
	switch s.spfResult {
	case spf.None:
		logrus.Warnf("SPF Result: NONE - No SPF record found for domain %s. Rejecting email.", getDomainFromEmail(s.from))
		return &smtp.SMTPError{Code: 450, EnhancedCode: smtp.EnhancedCode{5, 0, 0}, Message: "SPF check softfail (no SPF record)"}
	case spf.Neutral:
		logrus.Infof("SPF Result: NEUTRAL - Domain %s neither permits nor denies sending mail from IP %s", getDomainFromEmail(s.from), s.remoteIP)
	case spf.Pass:
		logrus.Infof("SPF Result: PASS - SPF check passed for domain %s, email is legitimate", getDomainFromEmail(s.from))
	case spf.Fail:
		logrus.Warnf("SPF Result: FAIL - SPF check failed for domain %s, mail from IP %s is unauthorized", getDomainFromEmail(s.from), s.remoteIP)
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "SPF check failed"}
	case spf.SoftFail:
		logrus.Warnf("SPF Result: SOFTFAIL - SPF check soft failed for domain %s, email is suspicious", getDomainFromEmail(s.from))
		return &smtp.SMTPError{Code: 450, EnhancedCode: smtp.EnhancedCode{5, 0, 1}, Message: "SPF check softfail"}
	case spf.TempError:
		logrus.Warnf("SPF Result: TEMPERROR - Temporary SPF error occurred for domain %s, retry might succeed", getDomainFromEmail(s.from))
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 0, 0}, Message: "Temporary SPF check error"}
	case spf.PermError:
		logrus.Warnf("SPF Result: PERMERROR - Permanent SPF error for domain %s, SPF record is invalid", getDomainFromEmail(s.from))
		return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 1, 2}, Message: "SPF check permanent error"}
	}
	return nil // SPF 检查通过，返回 nil
}
