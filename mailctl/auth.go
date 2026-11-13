package main

import (
	"fmt"
	"net/http"
	"os"
	"os/user"
	"path/filepath"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// Config is the ~/.mailctl/config.yaml structure.
type Config struct {
	Server string     `yaml:"server"`
	Auth   AuthConfig `yaml:"auth"`
}

// AuthConfig holds authentication settings.
type AuthConfig struct {
	Mode         string `yaml:"mode"` // "apikey" or "jwt"
	APIKey       string `yaml:"api_key,omitempty"`
	Token        string `yaml:"token,omitempty"`
	RefreshToken string `yaml:"refresh_token,omitempty"`
}

// LoadConfig reads ~/.mailctl/config.yaml.
func LoadConfig() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return &Config{}, nil // no config yet
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}

// configPathFn resolves the config file location; it is a package variable so
// tests can redirect the token store into a temporary directory instead of
// touching the operator's real HOME.
var configPathFn = configPath

// SaveConfig writes ~/.mailctl/config.yaml with 0600 permissions.
func SaveConfig(cfg *Config) error {
	path, err := configPathFn()
	if err != nil {
		return err
	}
	return saveConfigFile(path, cfg)
}

// saveConfigFile is the path-injectable body of SaveConfig. os.WriteFile
// applies its mode only when it CREATES the file, so a config.yaml that
// already exists with looser bits (an older mailctl, a manual copy, a
// restored home directory) would silently keep them and leave the stored
// access/refresh bearer tokens group/world-readable. The write is therefore
// followed by an unconditional tighten to 0600 — the same on-disk posture
// every mailctl credential input requires on read (readPrivateCredentialFile
// / readPrivateKeyFile: "must be a ... 0600 file"), never trusting the file
// to already carry the right mode.
func saveConfigFile(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

// runLogin is the modeConfig entrypoint for `mailctl login`. It manages the
// config file itself: validates the server-url arg, prompts for credentials,
// POSTs /auth/login (via Login, which builds its own Client from the server
// arg), and writes the config. It prints its own messages and exits — matching
// the old top-level switch exactly (NOT the generic "Error: %v" prefix), so a
// missing arg prints "Usage: mailctl login <server-url>" and a failure prints
// "Login failed: %v". args is the raw os.Args[2:].
func runLogin(c *cmdCtx, action string, args []string) error {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "Usage: mailctl login <server-url>\n")
		os.Exit(1)
	}
	cfg, err := Login(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Logged into %s\n", cfg.Server)
	return nil
}

// runLogout is the modeConfig entrypoint for `mailctl logout`. It rewrites the
// config file, clearing the tokens, then prints "Logged out." — byte-identical
// with the old top-level case (which ignores any extra args). args is unused.
func runLogout(c *cmdCtx, action string, args []string) error {
	cfg, _ := LoadConfig()
	if cfg != nil {
		cfg.Auth.Token = ""
		cfg.Auth.RefreshToken = ""
		SaveConfig(cfg)
	}
	fmt.Println("Logged out.")
	return nil
}

// Login prompts for credentials and obtains a JWT from the auth server.
func Login(server string) (*Config, error) {
	fmt.Print("Email: ")
	var email string
	fmt.Scanln(&email)

	fmt.Print("Password: ")
	pw, err := readPassword()
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}

	cl := &Client{Server: server, HTTP: &http.Client{}}
	var result struct {
		Token        string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := cl.Do("POST", "/auth/login", map[string]string{
		"email":    email,
		"password": pw,
	}, &result); err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	cfg := &Config{
		Server: server,
		Auth: AuthConfig{
			Mode:         "jwt",
			Token:        result.Token,
			RefreshToken: result.RefreshToken,
		},
	}
	if err := SaveConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func configPath() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(u.HomeDir, ".mailctl", "config.yaml"), nil
}

// readPassword reads a password from stdin without echo.
func readPassword() (string, error) {
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	fmt.Println() // newline after password prompt
	return string(pw), nil
}
