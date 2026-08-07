package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type manifest struct {
	DigestAlgorithm string `json:"digest_algorithm"`
	Fixtures        []struct {
		Path              string `json:"path"`
		Encoding          string `json:"encoding"`
		DecodedByteLength *int   `json:"decoded_byte_length"`
		StoredByteLength  *int   `json:"stored_byte_length"`
		SHA256            string `json:"sha256"`
	} `json:"fixtures"`
}

func TestGoldenVectorManifest(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", "..", "testvectors"))
	data, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var index manifest
	if err := json.Unmarshal(data, &index); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if index.DigestAlgorithm != "sha256" {
		t.Fatalf("unsupported digest algorithm %q", index.DigestAlgorithm)
	}
	if len(index.Fixtures) == 0 {
		t.Fatal("manifest contains no fixtures")
	}
	seen := make(map[string]struct{}, len(index.Fixtures))
	for _, fixture := range index.Fixtures {
		fixture := fixture
		t.Run(fixture.Path, func(t *testing.T) {
			clean := filepath.ToSlash(filepath.Clean(fixture.Path))
			if clean != fixture.Path || clean == "." || strings.HasPrefix(clean, "../") {
				t.Fatalf("noncanonical manifest path %q", fixture.Path)
			}
			if _, duplicate := seen[clean]; duplicate {
				t.Fatalf("duplicate manifest path %q", fixture.Path)
			}
			seen[clean] = struct{}{}
			want, err := hex.DecodeString(fixture.SHA256)
			if err != nil || len(want) != sha256.Size {
				t.Fatalf("invalid SHA-256 %q", fixture.SHA256)
			}
			contents, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fixture.Path)))
			if err != nil {
				t.Fatal(err)
			}
			got := sha256.Sum256(contents)
			if string(got[:]) != string(want) {
				t.Fatalf("digest mismatch: got %x want %x", got, want)
			}
			switch fixture.Encoding {
			case "hex":
				if fixture.DecodedByteLength == nil || fixture.StoredByteLength != nil {
					t.Fatal("hex fixture must have only decoded_byte_length")
				}
				decoded, err := hex.DecodeString(strings.Join(strings.Fields(string(contents)), ""))
				if err != nil || len(decoded) != *fixture.DecodedByteLength {
					t.Fatalf("decoded length=%d error=%v, want %d", len(decoded), err, *fixture.DecodedByteLength)
				}
			case "json-utf8", "utf8":
				if fixture.StoredByteLength == nil || fixture.DecodedByteLength != nil || len(contents) != *fixture.StoredByteLength {
					t.Fatalf("stored length=%d, declared=%v", len(contents), fixture.StoredByteLength)
				}
			default:
				t.Fatalf("unknown fixture encoding %q", fixture.Encoding)
			}
		})
	}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return walkErr
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		relative = filepath.ToSlash(relative)
		if relative == "README.md" || relative == "manifest.json" {
			return nil
		}
		if _, indexed := seen[relative]; !indexed {
			t.Errorf("fixture %q is not indexed by manifest.json", relative)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
