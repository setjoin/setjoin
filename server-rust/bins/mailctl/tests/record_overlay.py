"""Build-time recorder overlay only. Never changes tracked/frozen Go source."""
import json
from pathlib import Path
import sys

repo=Path(sys.argv[1]).resolve()
out=Path(sys.argv[2]).resolve();out.mkdir(parents=True,exist_ok=False)
main=(repo/'mailctl/main.go').read_text()
main=main.replace('import (','import (\n gofreeapns "github.com/sideshow/apns2"\n gofreetls "crypto/tls"\n gofreenet "net"',1)
main+='''
// The oracle changes only the socket destination; HTTP/2, certificate auth,
// payload generation, database access, stdout and exit status remain frozen.
func init() {
    target := os.Getenv("MAILCTL_ORACLE_APNS_ADDR")
    if target == "" { return }
    host, _, err := gofreenet.SplitHostPort(target)
    if err != nil || gofreenet.ParseIP(host) == nil || !gofreenet.ParseIP(host).IsLoopback() { panic("oracle APNs address must be loopback") }
    gofreeapns.DialTLS = func(network, address string, cfg *gofreetls.Config) (gofreenet.Conn, error) {
        copy := cfg.Clone()
        if copy.ServerName == "" { copy.ServerName, _, _ = gofreenet.SplitHostPort(address) }
        return gofreetls.Dial(network, target, copy)
    }
}
'''
push=(repo/'shared/push/push.go').read_text()
push=push.replace('"net/http"','"net/http"\n "net"\n "time"',1)
push=push.replace('return Config{','''return Config{
        WebPushHTTPClient: func() *http.Client {
            if os.Getenv("MAILCTL_ORACLE_WEBPUSH_LOOPBACK") != "1" { return nil }
            return &http.Client{Timeout: 30*time.Second, CheckRedirect: func(_ *http.Request,_ []*http.Request) error { return http.ErrUseLastResponse }, Transport: &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn,error) {
                host, _, err := net.SplitHostPort(address)
                if err != nil || net.ParseIP(host)==nil || !net.ParseIP(host).IsLoopback() { return nil,fmt.Errorf("oracle Web Push address must be loopback") }
                return (&net.Dialer{}).DialContext(ctx,network,address)
            }}}
        }(),''',1)
(out/'main.go').write_text(main);(out/'push.go').write_text(push)
# Docker mount paths are /src and /out, independent of the host worktree.
(out/'overlay.json').write_text(json.dumps({'Replace':{'/src/mailctl/main.go':'/out/record-overlay/main.go','/src/shared/push/push.go':'/out/record-overlay/push.go'}},indent=2)+'\n')
