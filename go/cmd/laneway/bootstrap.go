package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"time"

	"laneway.dev/laneway/internal/bootstrap"
)

func runBootstrap(args []string) error {
	if len(args) == 0 || (args[0] != "inspect" && args[0] != "download") {
		return errors.New("usage: laneway bootstrap <inspect|download> DOMAIN [options]")
	}
	command := args[0]
	fs := flag.NewFlagSet("bootstrap "+command, flag.ContinueOnError)
	out := fs.String("out", "", "exclusive output path for the verified release archive")
	commandArgs := args[1:]
	authority := ""
	if len(commandArgs) != 0 && commandArgs[0] != "" && commandArgs[0][0] != '-' {
		authority, commandArgs = commandArgs[0], commandArgs[1:]
	}
	if err := fs.Parse(commandArgs); err != nil {
		return err
	}
	if fs.NArg() > 1 || (fs.NArg() == 1 && authority != "") {
		return errors.New("usage: laneway bootstrap <inspect|download> DOMAIN [--out PATH]")
	}
	if fs.NArg() == 1 {
		authority = fs.Arg(0)
	}
	if authority == "" || (command == "download") != (*out != "") {
		return errors.New("bootstrap inspect requires DOMAIN; bootstrap download requires DOMAIN and --out PATH")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	metadata, err := bootstrap.Fetch(ctx, authority)
	cancel()
	if err != nil {
		return err
	}
	artifact, err := metadata.ArtifactForCurrentPlatform()
	if err != nil {
		return err
	}
	if command == "inspect" {
		return printJSON(struct {
			Metadata bootstrap.Metadata `json:"metadata"`
			Artifact bootstrap.Artifact `json:"current_platform_artifact"`
		}{Metadata: metadata, Artifact: artifact})
	}
	downloadCtx, downloadCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer downloadCancel()
	if err := bootstrap.DownloadArtifact(downloadCtx, artifact, *out); err != nil {
		return err
	}
	fmt.Printf("verified artifact %s/%s sha256=%s path=%s\n", artifact.OS, artifact.Arch, artifact.SHA256, *out)
	return nil
}
