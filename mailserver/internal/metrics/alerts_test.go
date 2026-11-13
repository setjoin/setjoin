package metrics

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type alertRuleFile struct {
	Groups []struct {
		Name  string `yaml:"name"`
		Rules []struct {
			Alert       string            `yaml:"alert"`
			Expr        string            `yaml:"expr"`
			For         string            `yaml:"for"`
			Labels      map[string]string `yaml:"labels"`
			Annotations map[string]string `yaml:"annotations"`
		} `yaml:"rules"`
	} `yaml:"groups"`
}

type zabbixRuleFile struct {
	Templates []struct {
		Items []struct {
			Key      string `xml:"key"`
			Triggers []struct {
				Name     string `xml:"name"`
				Priority string `xml:"priority"`
				URL      string `xml:"url"`
			} `xml:"triggers>trigger"`
		} `xml:"items>item"`
	} `xml:"templates>template"`
}

func TestIdentityAlertRulesPinSafetyContract(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/prometheus/identity-alerts.yml")
	if err != nil {
		t.Fatal(err)
	}
	var rules alertRuleFile
	if err := yaml.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("parse identity alert rules: %v", err)
	}
	if len(rules.Groups) != 1 || rules.Groups[0].Name != "setjoin-identity" {
		t.Fatalf("unexpected identity alert groups: %#v", rules.Groups)
	}

	want := map[string]struct {
		expr     string
		duration string
		severity string
	}{
		"SetjoinIdentityMetricsCollectorDown":      {"gateway_identity_collector_success != 1 or absent(gateway_identity_collector_success)", "2m", "critical"},
		"SetjoinIdentityCriticalDivergence":        {"setjoin_identity_shadow_divergences > 0", "1m", "critical"},
		"SetjoinIdentitySourceCursorStale":         {"setjoin_identity_cursor_age_seconds > 600", "10m", "warning"},
		"SetjoinIdentityInboxQuarantined":          {"gateway_identity_inbox_quarantined > 0", "5m", "warning"},
		"SetjoinIdentityTransitionEffectsStuck":    {"setjoin_identity_effect_intents > 0 and setjoin_identity_effect_oldest_age_seconds > 300", "5m", "warning"},
		"SetjoinIdentityTransitionEffectsCritical": {"setjoin_identity_effect_intents > 0 and setjoin_identity_effect_oldest_age_seconds > 1800", "5m", "critical"},
		"SetjoinIdentityTransitionStuck":           {"setjoin_identity_transitions > 0 and setjoin_identity_transition_age_seconds > 300", "5m", "warning"},
		"SetjoinIdentityApprovalExpiring":          {"gateway_identity_approvals_pending > 0 and gateway_identity_approval_expiry_seconds > 0 and gateway_identity_approval_expiry_seconds < 1800", "5m", "warning"},
		"SetjoinIdentitySourceAttention":           {"gateway_identity_sources_attention > 0 or gateway_identity_inbox_pending > 0", "15m", "warning"},
	}
	seen := make(map[string]bool, len(want))
	for _, rule := range rules.Groups[0].Rules {
		expected, ok := want[rule.Alert]
		if !ok {
			t.Fatalf("unreviewed identity alert %q", rule.Alert)
		}
		if seen[rule.Alert] {
			t.Fatalf("duplicate identity alert %q", rule.Alert)
		}
		seen[rule.Alert] = true
		if rule.Expr != expected.expr || rule.For != expected.duration {
			t.Errorf("%s contract drift: expr=%q for=%q", rule.Alert, rule.Expr, rule.For)
		}
		if len(rule.Labels) != 1 || rule.Labels["severity"] != expected.severity {
			t.Errorf("%s must have only the pinned severity label: %#v", rule.Alert, rule.Labels)
		}
		if rule.Annotations["summary"] == "" || rule.Annotations["runbook_url"] == "" {
			t.Errorf("%s must name a summary and exact runbook", rule.Alert)
		}
		for _, forbidden := range []string{"user_id", "subject", "link_id", "transition_id", "provider_name", "error_text"} {
			if strings.Contains(rule.Expr, forbidden) {
				t.Errorf("%s exposes forbidden high-cardinality selector %q", rule.Alert, forbidden)
			}
		}
	}
	for name := range want {
		if !seen[name] {
			t.Errorf("required identity alert %q is missing", name)
		}
	}
}

func TestIdentityZabbixRulesPinRunbooksAndSeverity(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/zabbix/setjoin-gateway.xml")
	if err != nil {
		t.Fatal(err)
	}
	var rules zabbixRuleFile
	if err := xml.Unmarshal(raw, &rules); err != nil {
		t.Fatalf("parse zabbix identity rules: %v", err)
	}
	if len(rules.Templates) != 1 {
		t.Fatalf("unexpected zabbix template count %d", len(rules.Templates))
	}
	required := map[string]bool{
		"gateway.identity.collector":         false,
		"gateway.identity.divergence":        false,
		"gateway.identity.cursor_age":        false,
		"gateway.identity.inbox_quarantined": false,
		"gateway.identity.transition_age":    false,
		"gateway.identity.effect_age":        false,
		"gateway.identity.approvals_pending": false,
		"gateway.identity.approval_expiry":   false,
	}
	for _, item := range rules.Templates[0].Items {
		if _, ok := required[item.Key]; !ok {
			continue
		}
		required[item.Key] = true
		for _, trigger := range item.Triggers {
			if trigger.Name == "" || trigger.Priority == "" || trigger.URL == "" {
				t.Errorf("%s identity trigger must pin name, severity, and runbook: %#v", item.Key, trigger)
			}
		}
	}
	for key, seen := range required {
		if !seen {
			t.Errorf("required identity Zabbix item %q is missing", key)
		}
	}
}

func TestZabbixMetricsScrapeKeepsBearerOutOfArguments(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/zabbix/userparameter_setjoin.conf")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "UserParameter=") || !strings.Contains(line, "/metrics") {
			continue
		}
		if !strings.Contains(line, "--config /etc/setjoin/metrics-curl.conf") {
			t.Errorf("metrics user parameter must use protected curl config: %s", line)
		}
		for _, forbidden := range []string{"Authorization:", "METRICS_TOKEN", "-H "} {
			if strings.Contains(line, forbidden) {
				t.Errorf("metrics user parameter leaks bearer material into argv: %s", line)
			}
		}
	}
}
