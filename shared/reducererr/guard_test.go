package reducererr

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"testing"
)

// bzRaise matches a reducer `... USING ERRCODE = 'BZ0xx'` raise.
var bzRaise = regexp.MustCompile(`ERRCODE\s*=\s*'(BZ\d+)'`)

// TestEveryRaisedBZCodeIsClassified is the machine guard for arch A1: it
// enumerates every BZ SQLSTATE any reducer (or trigger) RAISEs and asserts each
// is either classified in codeClass (a real 4xx ReplyClass) or listed in
// intentional500 (a deliberate 500). A new reducer that raises an unregistered
// BZ code fails THIS test at build time — instead of silently returning an
// opaque serverFail/500 to users in production, which is exactly how ~58 codes
// had drifted out of coverage before this guard existed.
//
// It anchors on the SQL as ground truth, so the Go classification can never fall
// behind the reducers again without a red test naming the offending code + file.
func TestEveryRaisedBZCodeIsClassified(t *testing.T) {
	raisedIn := map[string]string{} // code -> first file that raises it
	for _, dir := range []string{"../../mailserver/sql/reducers", "../../mailserver/sql/dbschema"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.sql"))
		if err != nil {
			t.Fatalf("glob %s: %v", dir, err)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatalf("read %s: %v", f, err)
			}
			for _, m := range bzRaise.FindAllStringSubmatch(string(b), -1) {
				if _, seen := raisedIn[m[1]]; !seen {
					raisedIn[m[1]] = f
				}
			}
		}
	}

	if len(raisedIn) == 0 {
		t.Fatal("found 0 BZ raises in sql/reducers + sql/dbschema — the glob paths are wrong (this test must see the SQL)")
	}

	var unclassified []string
	for code, file := range raisedIn {
		_, inClass := codeClass[code]
		if !inClass && !intentional500[code] {
			unclassified = append(unclassified, code+" (raised in "+filepath.Base(file)+")")
		}
	}
	sort.Strings(unclassified)
	for _, u := range unclassified {
		t.Errorf("BZ code %s is neither classified in codeClass nor listed in intentional500 — "+
			"it will silently project to serverFail/500. Add it to reducererr.codeClass (with a 4xx "+
			"ReplyClass) or, if a 500 is deliberate (an internal invariant), to intentional500.", u)
	}
	if len(unclassified) > 0 {
		t.Logf("%d raised BZ codes are unclassified (see errors above)", len(unclassified))
	}
}
