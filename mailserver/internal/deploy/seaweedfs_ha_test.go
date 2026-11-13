package deploy

import (
	"testing"
)

func TestComputeRaftPeers(t *testing.T) {
	nodes := []string{"10.0.1.11", "10.0.1.12", "10.0.1.13"}
	peers := computeRaftPeers(nodes, 9333)
	if len(peers) != 3 {
		t.Errorf("expected 3 peers, got %d", len(peers))
	}
	if peers[0] != "10.0.1.11:9333" {
		t.Errorf("peer[0] = %q", peers[0])
	}
}

func TestComputeRaftPeers_Single(t *testing.T) {
	nodes := []string{"10.0.1.11"}
	peers := computeRaftPeers(nodes, 9333)
	if len(peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(peers))
	}
}

func TestHaPlan_Validation(t *testing.T) {
	plan := HaPlan{
		Nodes:           []string{"10.0.1.11", "10.0.1.12", "10.0.1.13"},
		ReplicationMode: "001",
	}
	if len(plan.Nodes) != 3 {
		t.Error("should have 3 nodes")
	}
	if plan.ReplicationMode != "001" {
		t.Errorf("replication = %q, want 001", plan.ReplicationMode)
	}
}

func TestHaPlan_DefaultReplication(t *testing.T) {
	plan := HaPlan{
		Nodes: []string{"n1", "n2", "n3"},
	}
	configs := BuildHaConfig(plan)
	if len(configs) != 3 {
		t.Errorf("expected 3 configs, got %d", len(configs))
	}
	// Default replication is applied in BuildHaConfig
	if len(configs[0].Peers) != 3 {
		t.Errorf("expected 3 peers, got %d", len(configs[0].Peers))
	}
}

func TestBuildScaleDownPlan(t *testing.T) {
	nodes := []string{"10.0.1.11", "10.0.1.12", "10.0.1.13"}
	plan := BuildScaleDownPlan(nodes, "10.0.1.11", 9333)
	if plan.TargetNode != "10.0.1.11" {
		t.Errorf("target node = %q, want 10.0.1.11", plan.TargetNode)
	}
	if len(plan.NodesToRemove) != 2 {
		t.Errorf("nodes to remove = %d, want 2", len(plan.NodesToRemove))
	}
	for _, n := range plan.NodesToRemove {
		if n == "10.0.1.11" {
			t.Error("target node should not be in nodes to remove")
		}
	}
	if len(plan.Commands) == 0 {
		t.Error("should have post-deploy commands")
	}
}

func TestBuildScaleUpPlan(t *testing.T) {
	existing := "10.0.1.11"
	newNodes := []string{"10.0.1.12", "10.0.1.13"}
	plan := BuildScaleUpPlan(existing, newNodes, 9333, "/data/seaweedfs")

	if plan.ReplicationMode != "001" {
		t.Errorf("replication mode = %q, want 001", plan.ReplicationMode)
	}
	if len(plan.Nodes) != 3 {
		t.Errorf("nodes = %d, want 3", len(plan.Nodes))
	}
	if plan.Nodes[0] != existing {
		t.Errorf("first node should be existing node %q", existing)
	}
	if plan.VolumePath != "/data/seaweedfs" {
		t.Errorf("volume path = %q, want /data/seaweedfs", plan.VolumePath)
	}
}
