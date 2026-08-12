package main

import (
	"fmt"
	_ "net/http/pprof"
	"os"

	"crypto/rand"
	"encoding/hex"
	"net"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	URL         string `yaml:"url"`
	Token       string `yaml:"token,omitempty"`
	Hostname    string `yaml:"hostname"`
	IP          string `yaml:"ip"`
	Environment string `yaml:"environment"`
	Role        string `yaml:"role"`
	DBDriver    string `yaml:"db_driver,omitempty"`
	PostgresURL string `yaml:"postgres_url,omitempty"`
}

func generateToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateConfigFile() (ServerConfig, error) {
	const (
		configDir  = "/etc/klouddbshield"
		configPath = "/etc/klouddbshield/server-node.yaml"
	)
	var cfg ServerConfig

	if err := os.MkdirAll(configDir, 0o755); err != nil {
		fmt.Println("failed to create config dir:", err)
		return cfg, fmt.Errorf("We can not open directory %s: %w", configDir, err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		cfg = defaultServerConfig()

		if err := writeConfig(configPath, cfg); err != nil {
			return cfg, err
		}
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Println("failed to read config:", err)
		// fmt.Println("Using default config...")
		// cfg := defaultServerConfig()

		// writeConfig(configPath,cfg)
		// fmt.Println("server config create at : ",configPath)
		return cfg, fmt.Errorf("We can not open server config file at %s: %w", configPath, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("We can not unmarshal server config file at %s: %w", configPath, err)
	}

	changed := false

	if cfg.URL == "" {
		fmt.Println("Add a server URL")
	}

	if cfg.Hostname == "" {
		h, _ := os.Hostname()
		cfg.Hostname = h
		changed = true
	}

	if cfg.IP == "" {
		cfg.IP = detectLocalIP()
		changed = true
	}

	if cfg.Token == "" {
		token, err := generateToken(32)
		if err != nil {
			cfg.Token = uuid.NewString()
		} else {
			cfg.Token = token
		}
		changed = true
	}

	if cfg.Environment == "" {
		cfg.Environment = "dev"
		changed = true
	}

	if cfg.Role == "" {
		cfg.Role = "postgres"
		changed = true
	}

	if changed {
		if err := writeConfig(configPath, cfg); err != nil {
			return cfg, err
		}
		fmt.Println("agent config updated")
	}
	return cfg, nil
}

func defaultServerConfig() ServerConfig {
	var cfg ServerConfig

	cfg.URL = defaultServerURL()

	h, _ := os.Hostname()
	cfg.Hostname = h
	cfg.IP = detectLocalIP()
	cfg.Environment = "dev"
	cfg.Role = "postgres"
	token, err := generateToken(32)
	if err != nil {
		cfg.Token = uuid.NewString()
	} else {
		cfg.Token = token
	}

	return cfg
}

func writeConfig(path string, cfg ServerConfig) error {
	data, err := yaml.Marshal(&cfg)
	if err != nil {
		return fmt.Errorf("Failed to marshal config:%s", err)
	}

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("failed to write config:%s", err)
	}
	return nil
}

func detectLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "127.0.0.1"
	}

	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok &&
			!ipNet.IP.IsLoopback() &&
			ipNet.IP.To4() != nil {
			return ipNet.IP.String()
		}
	}
	return "127.0.0.1"
}
