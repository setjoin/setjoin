package main

import (
	"os"
	"strings"
	"testing"
)

func TestAuthserverWiresSharedToggleNotificationLifecycle(t *testing.T) {
	mainSource, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	runtimeSource, err := os.ReadFile("security_runtime.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mainSource), "toggle.BindNotifications(ctx, toggleListener") {
		t.Fatal("authserver composition root does not bind the shared toggle notification lifecycle")
	}
	for _, duplicate := range []string{"configureRequiredToggleListener", "json.Unmarshal([]byte(notification.Payload)"} {
		if strings.Contains(string(runtimeSource), duplicate) {
			t.Fatalf("authserver retained duplicate toggle lifecycle fragment %q", duplicate)
		}
	}
}
