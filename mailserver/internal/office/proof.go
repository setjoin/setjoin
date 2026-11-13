package office

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"setjoin.com/shared/ssrf"
)

const (
	proofClockSkew    = 20 * time.Minute
	proofCacheTTL     = 12 * time.Hour
	maxDiscovery      = 2 << 20
	windowsEpochTicks = uint64(621355968000000000)
	// minProofModulusBytes is the minimum RSA modulus size the WOPI proof
	// parser accepts (D-MAILSERVER-INTERNAL-OFFICE-002): 2048 bits. A smaller
	// published key would silently degrade proof validation to a forgeable
	// strength; discovery origins publishing such keys fail the fetch and
	// surface as a provider-health failure instead of a weak cache entry.
	minProofModulusBytes = 256
)

type proofKeys struct {
	current *rsa.PublicKey
	old     *rsa.PublicKey
	at      time.Time
}

type proofVerifier struct {
	client *http.Client
	now    func() time.Time
	mu     sync.Mutex
	cache  map[string]proofKeys
}

type discovery struct {
	ProofKey struct {
		Modulus     string `xml:"modulus,attr"`
		Exponent    string `xml:"exponent,attr"`
		OldModulus  string `xml:"oldmodulus,attr"`
		OldExponent string `xml:"oldexponent,attr"`
	} `xml:"proof-key"`
}

func newProofVerifier(client *http.Client) *proofVerifier {
	if client == nil {
		client = &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				// D-MAILSERVER-INTERNAL-OFFICE-001 (SSRF-OUTBOUND-FETCH /
				// INV6-PERIPHERAL-OUTBOUND-FETCH): runtime proof-key discovery
				// dials through the repo-standard ssrf guard — every A/AAAA
				// answer is resolved and checked, and a blocked answer fails
				// the dial — so a DNS repoint of an allow-listed hostname
				// cannot pivot the runtime fetch at internal addresses, the
				// same dial-time posture the qualification prober applies.
				// The discovery URL is admin-configured; an on-premise
				// private-address exception is represented by qualification's
				// PrivateAllow policy, which only a future provider-config
				// plumbing may extend to this client (a nil policy keeps
				// private addresses blocked).
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					return ssrf.DialContextWithPrivatePolicy(ctx, network, address, nil)
				},
				ForceAttemptHTTP2:   true,
				TLSHandshakeTimeout: 5 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) == 0 || len(via) >= 10 || !sameHTTPSOrigin(via[0].URL, req.URL) {
					return errors.New("WOPI discovery redirect left its HTTPS origin")
				}
				return nil
			},
		}
	}
	return &proofVerifier{client: client, now: time.Now, cache: make(map[string]proofKeys)}
}

func sameHTTPSOrigin(first, next *url.URL) bool {
	return first != nil && next != nil && first.Scheme == "https" && next.Scheme == "https" &&
		first.User == nil && next.User == nil && strings.EqualFold(first.Host, next.Host)
}

func validDiscoveryURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("WOPI discovery URL must be an absolute HTTPS URL without credentials or fragment")
	}
	return parsed, nil
}

func parsePublicKey(modulus, exponent string) (*rsa.PublicKey, error) {
	m, err := base64.StdEncoding.DecodeString(modulus)
	if err != nil || len(m) == 0 {
		return nil, errors.New("invalid WOPI proof modulus")
	}
	if len(m) < minProofModulusBytes {
		return nil, fmt.Errorf("WOPI proof modulus of %d bits is below the %d-bit floor",
			len(m)*8, minProofModulusBytes*8)
	}
	e, err := base64.StdEncoding.DecodeString(exponent)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, errors.New("invalid WOPI proof exponent")
	}
	var exponentValue uint32
	for _, b := range e {
		exponentValue = exponentValue<<8 | uint32(b)
	}
	if exponentValue < 3 || exponentValue > 1<<31-1 {
		return nil, errors.New("invalid WOPI proof exponent value")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(m), E: int(exponentValue)}, nil
}

func (v *proofVerifier) keys(ctx context.Context, discoveryURL string) (proofKeys, error) {
	expectedURL, err := validDiscoveryURL(discoveryURL)
	if err != nil {
		return proofKeys{}, err
	}
	v.mu.Lock()
	cached, ok := v.cache[discoveryURL]
	v.mu.Unlock()
	if ok && v.now().Sub(cached.at) < proofCacheTTL {
		return cached, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return proofKeys{}, err
	}
	res, err := v.client.Do(req)
	if err != nil {
		return proofKeys{}, fmt.Errorf("fetch WOPI discovery: %w", err)
	}
	defer res.Body.Close()
	if res.Request == nil || !sameHTTPSOrigin(expectedURL, res.Request.URL) {
		return proofKeys{}, errors.New("WOPI discovery response left its configured HTTPS origin")
	}
	if res.StatusCode != http.StatusOK {
		return proofKeys{}, fmt.Errorf("fetch WOPI discovery: status %d", res.StatusCode)
	}
	var doc discovery
	if err := xml.NewDecoder(io.LimitReader(res.Body, maxDiscovery)).Decode(&doc); err != nil {
		return proofKeys{}, fmt.Errorf("decode WOPI discovery: %w", err)
	}
	current, err := parsePublicKey(doc.ProofKey.Modulus, doc.ProofKey.Exponent)
	if err != nil {
		return proofKeys{}, err
	}
	keys := proofKeys{current: current, at: v.now()}
	if doc.ProofKey.OldModulus != "" && doc.ProofKey.OldExponent != "" {
		keys.old, err = parsePublicKey(doc.ProofKey.OldModulus, doc.ProofKey.OldExponent)
		if err != nil {
			return proofKeys{}, err
		}
	}
	v.mu.Lock()
	v.cache[discoveryURL] = keys
	v.mu.Unlock()
	return keys, nil
}

func proofPayload(accessToken, requestURL string, timestamp uint64) ([]byte, error) {
	parts := [][]byte{[]byte(accessToken), []byte(strings.ToUpper(requestURL))}
	var out []byte
	for _, part := range parts {
		if uint64(len(part)) > uint64(math.MaxUint32) {
			return nil, errors.New("WOPI proof field is too large")
		}
		length := make([]byte, 4)
		big.NewInt(int64(len(part))).FillBytes(length)
		out = append(out, length...)
		out = append(out, part...)
	}
	stampLength := make([]byte, 4)
	binary.BigEndian.PutUint32(stampLength, 8)
	out = append(out, stampLength...)
	stamp := make([]byte, 8)
	binary.BigEndian.PutUint64(stamp, timestamp)
	return append(out, stamp...), nil
}

func verifySignature(key *rsa.PublicKey, encoded string, digest []byte) bool {
	if key == nil || encoded == "" {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(encoded)
	return err == nil && rsa.VerifyPKCS1v15(key, crypto.SHA256, digest, sig) == nil
}

func (v *proofVerifier) verify(ctx context.Context, r *http.Request, accessToken, discoveryURL, publicBaseURL string) error {
	timestamp, err := strconv.ParseUint(r.Header.Get("X-WOPI-TimeStamp"), 10, 64)
	if err != nil {
		return errors.New("missing or invalid WOPI proof timestamp")
	}
	if timestamp < windowsEpochTicks {
		return errors.New("invalid WOPI proof timestamp epoch")
	}
	ticksSinceEpoch := timestamp - windowsEpochTicks
	if ticksSinceEpoch > uint64(math.MaxInt64/100) {
		return errors.New("invalid WOPI proof timestamp range")
	}
	stampTime := time.Unix(0, int64(ticksSinceEpoch)*100)
	delta := v.now().Sub(stampTime)
	if delta < -proofClockSkew || delta > proofClockSkew {
		return errors.New("WOPI proof timestamp outside allowed skew")
	}
	keys, err := v.keys(ctx, discoveryURL)
	if err != nil {
		return err
	}
	requestURL := strings.TrimRight(publicBaseURL, "/") + r.URL.RequestURI()
	payload, err := proofPayload(accessToken, requestURL, timestamp)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(payload)
	proof := r.Header.Get("X-WOPI-Proof")
	proofOld := r.Header.Get("X-WOPI-ProofOld")
	if verifySignature(keys.current, proof, digest[:]) ||
		verifySignature(keys.current, proofOld, digest[:]) ||
		verifySignature(keys.old, proof, digest[:]) {
		return nil
	}
	return errors.New("WOPI proof signature rejected")
}
