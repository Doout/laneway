package releasearchive

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type archiveEntry struct {
	name, contents string
	kind           byte
}

func TestExtractRegularFile(t *testing.T) {
	directory := t.TempDir()
	archive := testArchive(t, directory, []archiveEntry{
		{name: "laneway/", kind: tar.TypeDir},
		{name: "laneway/bin/laneway", contents: "verified-client", kind: tar.TypeReg},
	})
	destination := filepath.Join(directory, "client")
	if err := ExtractRegularFile(archive, "laneway/bin/laneway", destination, 0o700, 1024); err != nil {
		t.Fatal(err)
	}
	contents, err := os.ReadFile(destination)
	if err != nil || string(contents) != "verified-client" {
		t.Fatalf("contents=%q err=%v", contents, err)
	}
	if err := ExtractRegularFile(archive, "laneway/bin/laneway", destination, 0o700, 1024); err == nil {
		t.Fatal("overwrote existing destination")
	}
}

func TestExtractRegularFileRejectsUnsafeArchives(t *testing.T) {
	for name, entries := range map[string][]archiveEntry{
		"traversal": {{name: "../laneway/bin/laneway", contents: "bad", kind: tar.TypeReg}},
		"duplicate": {
			{name: "laneway/bin/laneway", contents: "one", kind: tar.TypeReg},
			{name: "laneway/bin/laneway", contents: "two", kind: tar.TypeReg},
		},
		"symlink":  {{name: "laneway/bin/laneway", contents: "target", kind: tar.TypeSymlink}},
		"oversize": {{name: "laneway/bin/laneway", contents: strings.Repeat("x", 32), kind: tar.TypeReg}},
		"missing":  {{name: "laneway/README.md", contents: "docs", kind: tar.TypeReg}},
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			archive := testArchive(t, directory, entries)
			destination := filepath.Join(directory, "client")
			if err := ExtractRegularFile(archive, "laneway/bin/laneway", destination, 0o700, 16); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, err := os.Lstat(destination); !os.IsNotExist(err) {
				t.Fatalf("failed extraction published destination: %v", err)
			}
		})
	}
}

func testArchive(t *testing.T, directory string, entries []archiveEntry) string {
	t.Helper()
	filename := filepath.Join(directory, "release.tar.gz")
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	compressed := gzip.NewWriter(file)
	archive := tar.NewWriter(compressed)
	for _, entry := range entries {
		size := int64(len(entry.contents))
		if entry.kind != tar.TypeReg {
			size = 0
		}
		if err := archive.WriteHeader(&tar.Header{Name: entry.name, Typeflag: entry.kind, Mode: 0o755, Size: size, Linkname: entry.contents}); err != nil {
			t.Fatal(err)
		}
		if entry.kind == tar.TypeReg {
			if _, err := archive.Write([]byte(entry.contents)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := compressed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return filename
}
