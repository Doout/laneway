// Command lanewayd is a compatibility wrapper for laneway node run.
package main

import (
	"fmt"
	"os"

	"laneway.dev/laneway/internal/nodeapp"
)

func main() {
	if err := nodeapp.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "lanewayd:", err)
		os.Exit(1)
	}
}
