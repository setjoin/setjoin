package deploy

import "fmt"

// PgpoolConfig holds parameters for generating a Pgpool-II systemd unit.
type PgpoolConfig struct {
	Backends   []string // host:port pairs
	ListenPort int
}

// GeneratePgpoolSystemdUnit produces a systemd service unit for Pgpool-II.
func GeneratePgpoolSystemdUnit(cfg PgpoolConfig) string {
	if cfg.ListenPort == 0 {
		cfg.ListenPort = 9999
	}
	backendList := ""
	for _, b := range cfg.Backends {
		backendList += fmt.Sprintf("# Backend: %s\n", b)
	}
	return fmt.Sprintf(`[Unit]
Description=Pgpool-II Connection Pooler
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=mail
ExecStart=/usr/local/bin/pgpool -n -f /etc/pgpool/pgpool.conf -p %d
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
LimitNOFILE=65536
%s
[Install]
WantedBy=multi-user.target
`, cfg.ListenPort, backendList)
}
