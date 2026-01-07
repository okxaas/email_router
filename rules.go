package main

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"
)

// RuleManager manages dynamic rules for blacklist and disabled recipients
type RuleManager struct {
	mu                 sync.RWMutex
	filePath           string
	Blacklist          map[string]bool
	DisabledRecipients map[string]bool
}

var Rules *RuleManager

// InitRuleManager initializes the rule manager
func InitRuleManager(filePath string) {
	Rules = &RuleManager{
		filePath:           filePath,
		Blacklist:          make(map[string]bool),
		DisabledRecipients: make(map[string]bool),
	}
	Rules.Load()
}

// Load reads rules from the JSON file
func (rm *RuleManager) Load() {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	data, err := os.ReadFile(rm.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			logrus.Errorf("Failed to load rules from %s: %v", rm.filePath, err)
		}
		return
	}

	var parsed struct {
		Blacklist          []string `json:"blacklist"`
		DisabledRecipients []string `json:"disabled_recipients"`
	}

	if err := json.Unmarshal(data, &parsed); err != nil {
		logrus.Errorf("Failed to parse rules from %s: %v", rm.filePath, err)
		return
	}

	// Reset maps
	rm.Blacklist = make(map[string]bool)
	rm.DisabledRecipients = make(map[string]bool)

	for _, v := range parsed.Blacklist {
		rm.Blacklist[strings.ToLower(v)] = true
	}
	for _, v := range parsed.DisabledRecipients {
		rm.DisabledRecipients[strings.ToLower(v)] = true
	}

	logrus.Infof("Loaded rules: %d blacklist items, %d disabled recipients", len(rm.Blacklist), len(rm.DisabledRecipients))
}

// Save writes rules to the JSON file
func (rm *RuleManager) Save() error {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	var blacklist []string
	for k := range rm.Blacklist {
		blacklist = append(blacklist, k)
	}
	sort.Strings(blacklist)

	var disabled []string
	for k := range rm.DisabledRecipients {
		disabled = append(disabled, k)
	}
	sort.Strings(disabled)

	data := struct {
		Blacklist          []string `json:"blacklist"`
		DisabledRecipients []string `json:"disabled_recipients"`
	}{
		Blacklist:          blacklist,
		DisabledRecipients: disabled,
	}

	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	// Ensure directory exists
	// Assuming filePath includes directory, but simpler if we just use a file in current dir or mapped volume
	return os.WriteFile(rm.filePath, bytes, 0644)
}

// AddBlacklist adds an email or domain to blacklist
func (rm *RuleManager) AddBlacklist(item string) error {
	rm.mu.Lock()
	rm.Blacklist[strings.ToLower(item)] = true
	rm.mu.Unlock()
	return rm.Save()
}

// RemoveBlacklist removes an item from blacklist
func (rm *RuleManager) RemoveBlacklist(item string) error {
	rm.mu.Lock()
	delete(rm.Blacklist, strings.ToLower(item))
	rm.mu.Unlock()
	return rm.Save()
}

// AddDisabledRecipient adds an alias to disabled list
func (rm *RuleManager) AddDisabledRecipient(item string) error {
	rm.mu.Lock()
	rm.DisabledRecipients[strings.ToLower(item)] = true
	rm.mu.Unlock()
	return rm.Save()
}

// RemoveDisabledRecipient removes an alias from disabled list
func (rm *RuleManager) RemoveDisabledRecipient(item string) error {
	rm.mu.Lock()
	delete(rm.DisabledRecipients, strings.ToLower(item))
	rm.mu.Unlock()
	return rm.Save()
}

// IsBlacklisted checks if an email is blacklisted (checks dynamic rules AND static config)
func (rm *RuleManager) IsBlacklisted(email string) bool {
	email = strings.ToLower(email)

	// Check static config first (config.yml)
	if checkStaticBlacklist(email) {
		return true
	}

	rm.mu.RLock()
	defer rm.mu.RUnlock()

	for rule := range rm.Blacklist {
		// 1. Exact Match
		if email == rule {
			return true
		}
		// 2. Domain Match (@domain.com)
		if strings.HasPrefix(rule, "@") && strings.HasSuffix(email, rule) {
			return true
		}
		// 3. Bare Domain Match (domain.com) -> match @domain.com
		if !strings.Contains(rule, "@") && strings.HasSuffix(email, "@"+rule) {
			return true
		}
	}
	return false
}

// IsDisabledRecipient checks if recipient alias is disabled
func (rm *RuleManager) IsDisabledRecipient(recipient string) bool {
	recipient = strings.ToLower(recipient)

	// Check static config first
	if checkStaticDisabledRecipient(recipient) {
		return true
	}

	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.DisabledRecipients[recipient]
}

// Helper functions for static config check (moved/adapted from func.go logic)
func checkStaticBlacklist(email string) bool {
	for _, rule := range CONFIG.SMTP.Blacklist {
		rule = strings.ToLower(rule)
		if email == rule {
			return true
		}
		if strings.HasPrefix(rule, "@") && strings.HasSuffix(email, rule) {
			return true
		}
		if !strings.Contains(rule, "@") && strings.HasSuffix(email, "@"+rule) {
			return true
		}
	}
	return false
}

func checkStaticDisabledRecipient(recipient string) bool {
	for _, disabled := range CONFIG.SMTP.DisabledRecipients {
		if recipient == strings.ToLower(disabled) {
			return true
		}
	}
	return false
}
