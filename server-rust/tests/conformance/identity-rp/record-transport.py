#!/usr/bin/env python3
"""Generate a Go coverage overlay for the external synthetic IdP transport only."""
import json, sys
from pathlib import Path
root=Path(__file__).resolve().parents[4]
out=Path(sys.argv[1]).resolve()
out.mkdir(exist_ok=True,parents=True)
source=root/'authserver/internal/federation/oidc_rp.go'
text=source.read_text().replace('"context"','"context"\n"crypto/tls"\n"crypto/x509"\n"net"\n"os"')
old='return ssrf.SafeHTTPClient(oidcDiscoveryTimeout)'
new='''client := ssrf.SafeHTTPClient(oidcDiscoveryTimeout)
    if addr := os.Getenv("IDFED2_IDP_ADDR"); addr != "" {
        ca, err := os.ReadFile(os.Getenv("IDFED2_IDP_CA")); if err != nil { panic(err) }
        roots := x509.NewCertPool(); if !roots.AppendCertsFromPEM(ca) { panic("invalid fixture CA") }
        original := client.Transport.(*http.Transport)
        guarded := original.DialContext
        transport := original.Clone()
        transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
        transport.DialContext = func(ctx context.Context, network, address string)(net.Conn,error){
            host,_,err:=net.SplitHostPort(address)
            if err==nil && host=="idp.idfed2.test" { return (&net.Dialer{Timeout:oidcDiscoveryTimeout}).DialContext(ctx,network,addr) }
            return guarded(ctx,network,address)
        }
        client.Transport=transport
    }
    return client'''
assert text.count(old)==1
patch=out/'oidc_rp.go';patch.write_text(text.replace(old,new))
(out/'overlay.json').write_text(json.dumps({'Replace':{str(source):str(patch),'/src/authserver/internal/federation/oidc_rp.go':str(patch)}}))
