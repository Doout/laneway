package releaseupdate

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

func TestExtractMacClientRequiresMatchingRealMembers(t *testing.T) {
	type item struct {
		name, body string
		kind       byte
	}
	cli := item{"laneway/bin/laneway", "operator CLI", tar.TypeReg}
	runtime := item{"laneway/bin/lanewayd-rs", "Rust runtime", tar.TypeReg}
	marker := item{"laneway/macos-runtime", "rust-v1\n", tar.TypeReg}
	version := item{"laneway/VERSION", "1.2.3\n", tar.TypeReg}
	for _, tc := range []struct {
		name    string
		members []item
		valid   bool
	}{
		{"matched", []item{cli, runtime, marker, version, {"laneway/bin/lane", "", tar.TypeSymlink}}, true},
		{"no runtime", []item{cli, marker, version}, false},
		{"old package", []item{cli, runtime, version}, false},
		{"wrong version", []item{cli, runtime, marker, {version.name, "1.2.4\n", tar.TypeReg}}, false},
		{"duplicate", []item{cli, runtime, marker, version, runtime}, false},
		{"symlink runtime", []item{cli, {runtime.name, "", tar.TypeSymlink}, marker, version}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			archive := filepath.Join(directory, "archive.tar.gz")
			file, err := os.Create(archive)
			if err != nil {
				t.Fatal(err)
			}
			compressed := gzip.NewWriter(file)
			writer := tar.NewWriter(compressed)
			for _, member := range tc.members {
				header := &tar.Header{Name: member.name, Typeflag: member.kind, Mode: 0o755, Size: int64(len(member.body))}
				if member.kind == tar.TypeSymlink {
					header.Linkname = "laneway"
				}
				if err := writer.WriteHeader(header); err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write([]byte(member.body)); err != nil {
					t.Fatal(err)
				}
			}
			for _, stream := range []interface{ Close() error }{writer, compressed, file} {
				if err := stream.Close(); err != nil {
					t.Fatal(err)
				}
			}
			client, daemon, err := ExtractMacClient(archive, directory, "1.2.3", 4096)
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v, extract returned %v", tc.valid, err)
			}
			if !tc.valid {
				return
			}
			for path, expected := range map[string]string{client: cli.body, daemon: runtime.body} {
				actual, err := os.ReadFile(path)
				if err != nil || string(actual) != expected {
					t.Fatalf("unexpected executable %s: %q (%v)", path, actual, err)
				}
			}
			if _, err := os.Lstat(filepath.Join(directory, "lane")); !os.IsNotExist(err) {
				t.Fatalf("archive alias must not be extracted: %v", err)
			}
		})
	}
}
