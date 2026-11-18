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
	if version == "" || len(version) > 64 || strings.ContainsAny(version, "\r\n\x00") || binaryLimit <= 0 || binaryLimit > 256<<20 {
		return "", "", errors.New("invalid macOS package extraction parameters")
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
	limit := &io.LimitedReader{R: compressed, N: 2*binaryLimit + (4 << 20)}
	reader := tar.NewReader(limit)
	binaries := map[string]string{
		"laneway/bin/laneway":     filepath.Join(directory, "laneway"),
		"laneway/bin/lanewayd-rs": filepath.Join(directory, "lanewayd-rs"),
	}
	metadata := map[string]string{
		"laneway/macos-runtime": macRuntimeFormat + "\n",
		"laneway/VERSION":       version + "\n",
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
			return "", "", fmt.Errorf("invalid or duplicate macOS package member %s", header.Name)
		}
		seen[header.Name] = true
		if text {
			if header.Size != int64(len(expected)) {
				return "", "", fmt.Errorf("unexpected macOS package metadata in %s", header.Name)
			}
			contents, err := io.ReadAll(reader)
			if err != nil || string(contents) != expected {
				return "", "", fmt.Errorf("unexpected macOS package metadata in %s", header.Name)
			}
			continue
		}
		if header.Mode&0o111 == 0 {
			return "", "", fmt.Errorf("macOS package member is not executable: %s", header.Name)
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
		return "", "", errors.New("macOS archive does not contain the complete Rust package")
	}
	return binaries["laneway/bin/laneway"], binaries["laneway/bin/lanewayd-rs"], nil
}
