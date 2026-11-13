package tlsutil

// Records the frozen monitor's database effect for replay by Rust.
import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"setjoin.com/shared/testsupport"
)

type certOracleRow struct {
	Case      string `json:"case"`
	CheckName string `json:"check_name"`
	Status    string `json:"status"`
	Value     int    `json:"value"`
	Threshold int    `json:"threshold"`
	Details   string `json:"details"`
}

func TestCertMonitorWorkerOracle(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var ids []int64
	defer func() {
		if len(ids) > 0 {
			if _, err := pool.Exec(context.Background(), `DELETE FROM health_history WHERE id=ANY($1::bigint[])`, ids); err != nil {
				t.Errorf("cleanup: %v", err)
			}
		}
	}()
	date := regexp.MustCompile(`\d{4}-\d{2}-\d{2}`)
	var got []certOracleRow
	for _, tc := range []struct {
		name    string
		days    int
		noCert  bool
		dnsOnly bool
	}{
		{"none", 0, true, false}, {"expired", -2, false, false}, {"seven", 7, false, false},
		{"fourteen", 14, false, true}, {"thirty", 30, false, false}, {"healthy", 31, false, false},
	} {
		var before int64
		if err := pool.QueryRow(ctx, `SELECT COALESCE(max(id),0) FROM health_history`).Scan(&before); err != nil {
			t.Fatal(err)
		}
		subject := "gofree-t10-" + tc.name + ".invalid"
		certs := []*x509.Certificate{}
		if !tc.noCert {
			cert := &x509.Certificate{Subject: pkix.Name{CommonName: subject}, NotAfter: time.Now().UTC().Add(time.Duration(tc.days)*24*time.Hour + 12*time.Hour)}
			if tc.dnsOnly {
				cert.Subject.CommonName = ""
				cert.DNSNames = []string{subject}
			}
			// A later chain certificate must not hide the earliest expiry.
			certs = []*x509.Certificate{{Subject: pkix.Name{CommonName: "later.invalid"}, NotAfter: time.Now().Add(100 * 24 * time.Hour)}, cert}
		}
		workerCtx, stop := context.WithCancel(ctx)
		done := make(chan struct{})
		go func() {
			defer close(done)
			NewCertMonitor(pool, testsupport.TestLogger(), func() []*x509.Certificate { return certs }).Run(workerCtx, 24*time.Hour)
		}()
		var id int64
		var row certOracleRow
		row.Case = tc.name
		match := "%" + subject + "%"
		if tc.noCert {
			match = "no TLS certificates loaded"
		}
		for {
			err := pool.QueryRow(ctx, `SELECT id, check_name, status, value::int, threshold::int, details FROM health_history WHERE id>$1 AND check_name='tls_cert' AND details LIKE $2 ORDER BY id DESC LIMIT 1`, before, match).Scan(&id, &row.CheckName, &row.Status, &row.Value, &row.Threshold, &row.Details)
			if err == nil {
				break
			}
			if !errors.Is(err, pgx.ErrNoRows) || ctx.Err() != nil {
				stop()
				<-done
				t.Fatal(err)
			}
			time.Sleep(10 * time.Millisecond)
		}
		stop()
		<-done
		ids = append(ids, id)
		row.Details = date.ReplaceAllString(strings.ReplaceAll(row.Details, subject, "SUBJECT"), "DATE")
		got = append(got, row)
	}
	if path := os.Getenv("GOFREE_RECORD_CERT_MONITOR"); path != "" {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			t.Fatal(err)
		}
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(got); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	data, err := os.ReadFile("../../../server-rust/bins/gateway/tests/golden/go-cert-monitor.json")
	if err != nil {
		t.Fatal(err)
	}
	var want []certOracleRow
	if err := json.Unmarshal(data, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal(fmt.Sprintf("monitor oracle: got %+v; want %+v", got, want))
	}
}
