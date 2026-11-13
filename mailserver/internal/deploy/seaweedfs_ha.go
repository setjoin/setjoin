package deploy

import "fmt"

// HaPlan describes a SeaweedFS HA deployment configuration.
type HaPlan struct {
	Nodes           []string // server IPs or hostnames
	ReplicationMode string   // "000" (none), "001" (async), "002" (sync)
	VolumePath      string   // per-node volume path (default /data/seaweedfs)
	S3Port          int      // S3 gateway port per node (default 9000)
	MasterPort      int      // master peer port (default 9333)
	MaxVolumes      int      // max volumes per node (default 100)
	Rack            string   // rack identifier (default "rack1")
}

// computeRaftPeers builds the -master.peers list from node addresses and master port.
func computeRaftPeers(nodes []string, masterPort int) []string {
	peers := make([]string, len(nodes))
	for i, node := range nodes {
		peers[i] = fmt.Sprintf("%s:%d", node, masterPort)
	}
	return peers
}

// BuildHaConfig computes the full deployment configuration from a plan.
func BuildHaConfig(plan HaPlan) []SeaweedFSNodeConfig {
	// Apply defaults
	if plan.ReplicationMode == "" {
		plan.ReplicationMode = "001"
	}
	if plan.S3Port == 0 {
		plan.S3Port = 9000
	}
	if plan.MasterPort == 0 {
		plan.MasterPort = 9333
	}
	if plan.MaxVolumes == 0 {
		plan.MaxVolumes = 100
	}
	if plan.Rack == "" {
		plan.Rack = "rack1"
	}
	if plan.VolumePath == "" {
		plan.VolumePath = "/data/seaweedfs"
	}

	peers := computeRaftPeers(plan.Nodes, plan.MasterPort)

	configs := make([]SeaweedFSNodeConfig, len(plan.Nodes))
	for i, node := range plan.Nodes {
		configs[i] = SeaweedFSNodeConfig{
			VolumePath: plan.VolumePath,
			Peers:      peers,
			S3Port:     plan.S3Port,
			Rack:       fmt.Sprintf("%s-%s", plan.Rack, node),
			MaxVolumes: plan.MaxVolumes,
		}
	}
	return configs
}

// BuildPostDeployCommands generates shell commands to run after all nodes are up:
// set replication, balance volumes, verify cluster health.
func BuildPostDeployCommands(plan HaPlan) []string {
	return []string{
		fmt.Sprintf("weed shell -master=%s volume.configure.replication %s",
			plan.Nodes[0]+fmt.Sprintf(":%d", plan.MasterPort), plan.ReplicationMode),
		fmt.Sprintf("weed shell -master=%s volume.balance",
			plan.Nodes[0]+fmt.Sprintf(":%d", plan.MasterPort)),
		fmt.Sprintf("curl -s http://%s:%d/cluster/status",
			plan.Nodes[0], plan.MasterPort),
	}
}

// ScaleDownPlan describes how to consolidate a 3-node cluster to a single node.
type ScaleDownPlan struct {
	TargetNode    string
	NodesToRemove []string
	Commands      []string
}

// BuildScaleDownPlan creates a plan to scale down from a cluster to a single node.
func BuildScaleDownPlan(allNodes []string, targetNode string, masterPort int) ScaleDownPlan {
	var toRemove []string
	for _, n := range allNodes {
		if n != targetNode {
			toRemove = append(toRemove, n)
		}
	}
	return ScaleDownPlan{
		TargetNode:    targetNode,
		NodesToRemove: toRemove,
		Commands: []string{
			fmt.Sprintf("weed shell -master=%s:%d volume.configure.replication 000",
				targetNode, masterPort),
			fmt.Sprintf("weed shell -master=%s:%d volume.move -source=%s -target=%s",
				targetNode, masterPort, toRemove[0], targetNode),
			fmt.Sprintf("weed shell -master=%s:%d volume.move -source=%s -target=%s",
				targetNode, masterPort, toRemove[1], targetNode),
		},
	}
}

// BuildScaleUpPlan creates an HaPlan for scaling up from single node to a 3-node cluster.
func BuildScaleUpPlan(existingNode string, newNodeIPs []string, masterPort int, volumePath string) HaPlan {
	nodes := append([]string{existingNode}, newNodeIPs...)
	return HaPlan{
		Nodes:           nodes,
		ReplicationMode: "001",
		MasterPort:      masterPort,
		VolumePath:      volumePath,
	}
}
