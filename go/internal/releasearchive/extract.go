package releasearchive

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// ExtractRegularFile publishes exactly one bounded regular-file member from a
// gzip-compressed tar archive without overwriting an existing destination.
func ExtractRegularFile(archive, member, destination string, mode os.FileMode, maxSize int64) error {
	if member == "" || path.Clean(member) != member || path.IsAbs(member) || maxSize <= 0 {
		return errors.New("release archive extraction parameters are invalid")
	}
	input, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer input.Close()
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return fmt.Errorf("open verified release archive: %w", err)
	}
	defer compressed.Close()
	reader := tar.NewReader(compressed)
	found := false
	var staged string
	defer func() {
		if staged != "" {
			_ = os.Remove(staged)
		}
	}()
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read verified release archive: %w", err)
		}
		archiveName := strings.TrimSuffix(header.Name, "/")
		clean := path.Clean(archiveName)
		if clean != archiveName || strings.HasPrefix(clean, "../") || path.IsAbs(clean) {
			return errors.New("verified release archive contains an unsafe path")
		}
		if clean != member {
			continue
		}
		if found || header.Typeflag != tar.TypeReg || header.Size <= 0 || header.Size > maxSize {
			return errors.New("verified release archive contains an invalid client binary")
		}
		output, err := os.CreateTemp(filepath.Dir(destination), ".laneway-release-*")
		if err != nil {
			return err
		}
		staged = output.Name()
		if err := output.Chmod(mode); err != nil {
			_ = output.Close()
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(reader, header.Size+1))
		closeErr := output.Close()
		if copyErr != nil || closeErr != nil || written != header.Size {
			_ = os.Remove(destination)
			return errors.New("extract verified client binary failed")
		}
		found = true
	}
	if !found {
		return fmt.Errorf("verified release archive does not contain %s", member)
	}
	if err := os.Link(staged, destination); err != nil {
		return fmt.Errorf("publish verified release file without replacement: %w", err)
	}
	return nil
}
