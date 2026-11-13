package deploy

import (
	"strings"
	"testing"
)

func TestGenerateSystemdUnit(t *testing.T) {
	cfg := SeaweedFSNodeConfig{
		VolumePath: "/data/seaweedfs",
		Peers:      []string{"node1:9333", "node2:9333", "node3:9333"},
		S3Port:     9000,
		Rack:       "rack1",
		MaxVolumes: 100,
	}
	unit := GenerateSystemdUnit(cfg)

	checks := []string{
		"[Unit]",
		"Description=SeaweedFS Storage Node",
		"After=network.target",
		"[Service]",
		"Type=simple",
		"User=mail",
		"-dir=/data/seaweedfs",
		"-master.peers=node1:9333,node2:9333,node3:9333",
		"-filer",
		"-s3",
		"-s3.port=9000",
		"-volume.max=100",
		"-rack=rack1",
		"-dataCenter=dc1",
		"Restart=always",
		"RestartSec=10",
		"[Install]",
		"WantedBy=multi-user.target",
	}
	for _, want := range checks {
		if !strings.Contains(unit, want) {
			t.Errorf("unit missing: %q", want)
		}
	}
}

func TestGenerateSystemdUnit_SingleNode(t *testing.T) {
	cfg := SeaweedFSNodeConfig{
		VolumePath: "/mnt/ssd/seaweedfs",
		Peers:      nil,
		S3Port:     9000,
		MaxVolumes: 50,
	}
	unit := GenerateSystemdUnit(cfg)

	if !strings.Contains(unit, "-dir=/mnt/ssd/seaweedfs") {
		t.Error("should use configured volume path")
	}
	if strings.Contains(unit, "-master.peers=") {
		t.Error("single node should not have master.peers")
	}
}

func TestGenerateSystemdUnit_DefaultValues(t *testing.T) {
	cfg := SeaweedFSNodeConfig{}
	unit := GenerateSystemdUnit(cfg)
	if len(unit) < 100 {
		t.Error("unit should be at least 100 characters")
	}
}
