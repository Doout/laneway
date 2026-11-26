package releaseupdate

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const macRuntimeFormat = "rust-v1"

// ExtractMacClient reads only the two executable members of a verified macOS
// archive. Archive-controlled paths and links are never extracted.
func ExtractMacClient(archive, directory, version string, binaryLimit int64) (string, string, error) {
	return extractClient(archive, directory, version, binaryLimit, "laneway/bin/lanewayd-rs", true)
}

// ExtractLinuxClient stages only the verified CLI and Rust runner.
func ExtractLinuxClient(archive, directory, version string, binaryLimit int64) (string, string, error) {
	return extractClient(archive, directory, version, binaryLimit, "laneway/sbin/lanewayd-rs", false)
}

func extractClient(archive, directory, version string, binaryLimit int64, daemon string, mac bool) (string, string, error) {
	if version == "" || len(version) > 64 || strings.ContainsAny(version, "\r\n\x00") || binaryLimit <= 0 || binaryLimit > 256<<20 {
		return "", "", errors.New("invalid client package extraction parameters")
	}
	file, err := os.Open(archive)
	if err != nil {
		return "", "", err
	}
	defer file.Close()
	compressed, err := gzip.NewReader(file)
	if err != nil {
		return "", "", err
	}
	defer compressed.Close()
	limit := &io.LimitedReader{R: compressed, N: 6*binaryLimit + (32 << 20)}
	reader := tar.NewReader(limit)
	binaries := map[string]string{
		"laneway/bin/laneway": filepath.Join(directory, "laneway"),
		daemon:                filepath.Join(directory, "lanewayd-rs"),
	}
	metadata := map[string]string{
		"laneway/VERSION": version + "\n",
	}
	if mac {
		metadata["laneway/macos-runtime"] = macRuntimeFormat + "\n"
	}
	seen := make(map[string]bool, len(binaries)+len(metadata))
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", "", err
		}
		destination, binary := binaries[header.Name]
		expected, text := metadata[header.Name]
		if !binary && !text {
			continue
		}
		if seen[header.Name] || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > binaryLimit {
			return "", "", fmt.Errorf("invalid or duplicate client package member %s", header.Name)
		}
		seen[header.Name] = true
		if text {
			if header.Size != int64(len(expected)) {
				return "", "", fmt.Errorf("unexpected client package metadata in %s", header.Name)
			}
			contents, err := io.ReadAll(reader)
			if err != nil || string(contents) != expected {
				return "", "", fmt.Errorf("unexpected client package metadata in %s", header.Name)
			}
			continue
		}
		if header.Mode&0o111 == 0 {
			return "", "", fmt.Errorf("client package member is not executable: %s", header.Name)
		}
		output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
		if err != nil {
			return "", "", err
		}
		_, copyErr := io.CopyN(output, reader, header.Size)
		if err := errors.Join(copyErr, output.Close()); err != nil {
			return "", "", err
		}
	}
	if limit.N == 0 || len(seen) != len(binaries)+len(metadata) {
		return "", "", errors.New("client archive does not contain the complete Rust package")
	}
	return binaries["laneway/bin/laneway"], binaries[daemon], nil
}
