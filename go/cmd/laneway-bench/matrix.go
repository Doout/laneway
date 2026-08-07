package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

var benchmarkScenarios = []string{"native-udp", "quic-stream", "direct-quic", "relay-quic", "relay-tcp", "subnet-forward", "exit-forward"}
var externalBenchmarkScenarios = []string{"rust-relay-quic", "rust-relay-tcp"}

func runBenchmarkMatrix(parent context.Context, args []string) error {
	fs := flag.NewFlagSet("matrix", flag.ContinueOnError)
	scenariosValue := fs.String("scenarios", "all", "comma-separated scenarios or all")
	flowsValue := fs.String("flows", "1", "comma-separated logical flow counts: 1,10,100")
	sizesValue := fs.String("sizes", "small,mtu", "comma-separated packet sizes; small=64, mtu=1200")
	profilesValue := fs.String("profiles", "lan", "comma-separated profiles: lan,wan")
	duration := fs.Duration("duration", 250*time.Millisecond, "duration of each matrix row")
	rate := fs.Uint64("pps", 1000, "packet rate per row; zero is unlimited")
	queue := fs.Int("queue", 256, "bounded relay/in-memory queue capacity")
	loss := fs.Float64("loss", 0, "deterministic random loss percentage [0,100]")
	burst := fs.Int("burst-loss", 0, "drop this many packets after each 100 offered packets")
	seed := fs.Int64("seed", 1, "loss PRNG seed")
	relayBinary := fs.String("rust-relay-binary", "", "path to release laneway-relay for rust-relay-* scenarios")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *duration <= 0 || *queue <= 0 || *queue > 4096 {
		return errors.New("duration must be positive and matrix queue must be in [1,4096]")
	}
	scenarios, err := parseScenarios(*scenariosValue)
	if err != nil {
		return err
	}
	flows, err := parseMatrixIntegers(*flowsValue, map[string]int{}, validFlowCount, "flows")
	if err != nil {
		return err
	}
	sizes, err := parseMatrixIntegers(*sizesValue, map[string]int{"small": 64, "mtu": 1200}, func(size int) bool {
		return size >= ipv4HeaderLen+benchmarkMetaLen && size <= maxQUICPacketSize
	}, "sizes")
	if err != nil {
		return err
	}
	profiles := splitNonempty(*profilesValue)
	if len(profiles) == 0 {
		return errors.New("profiles must not be empty")
	}
	row := 0
	for _, scenario := range scenarios {
		for _, flowCount := range flows {
			for _, packetSize := range sizes {
				for _, profile := range profiles {
					delay, validationErr := validateMatrixDimensions(flowCount, profile, -1, *loss, *burst)
					if validationErr != nil {
						return validationErr
					}
					row++
					fmt.Fprintf(os.Stdout, "matrix_row=%d scenario=%s flows=%d size=%d profile=%s\n", row, scenario, flowCount, packetSize, profile)
					options := quicBenchmarkOptions{
						duration: *duration, packetSize: packetSize, packetsPS: *rate, queue: *queue,
						flows: flowCount, profile: profile, delay: delay, loss: *loss, burstLoss: *burst, seed: *seed,
						relayBinary: *relayBinary,
					}
					var result quicBenchmarkResult
					var runErr error
					switch scenario {
					case "native-udp":
						result, runErr = runNativeUDPBenchmark(parent, options)
					case "quic-stream":
						result, runErr = runAuthenticatedQUICStreamBenchmark(parent, options)
					case "direct-quic":
						result, runErr = runAuthenticatedDirectBenchmark(parent, options)
					case "relay-quic":
						result, runErr = runAuthenticatedRelayBenchmark(parent, options, false)
					case "relay-tcp":
						result, runErr = runAuthenticatedRelayBenchmark(parent, options, true)
					case "subnet-forward":
						result, runErr = runDataplaneForwardingBenchmark(parent, options, false)
					case "exit-forward":
						result, runErr = runDataplaneForwardingBenchmark(parent, options, true)
					case "rust-relay-quic":
						result, runErr = runAuthenticatedExternalRustRelayBenchmark(parent, options, false, options.relayBinary)
					case "rust-relay-tcp":
						result, runErr = runAuthenticatedExternalRustRelayBenchmark(parent, options, true, options.relayBinary)
					}
					if runErr != nil {
						return fmt.Errorf("matrix row %d (%s): %w", row, scenario, runErr)
					}
					printBenchmarkSummary(os.Stdout, result)
				}
			}
		}
	}
	return nil
}

func parseScenarios(value string) ([]string, error) {
	items := splitNonempty(value)
	if len(items) == 1 && items[0] == "all" {
		return append([]string(nil), benchmarkScenarios...), nil
	}
	valid := make(map[string]bool, len(benchmarkScenarios))
	for _, scenario := range benchmarkScenarios {
		valid[scenario] = true
	}
	for _, scenario := range externalBenchmarkScenarios {
		valid[scenario] = true
	}
	for _, item := range items {
		if !valid[item] {
			return nil, fmt.Errorf("unknown matrix scenario %q", item)
		}
	}
	if len(items) == 0 {
		return nil, errors.New("scenarios must not be empty")
	}
	return items, nil
}

func parseMatrixIntegers(value string, aliases map[string]int, valid func(int) bool, name string) ([]int, error) {
	items := splitNonempty(value)
	result := make([]int, 0, len(items))
	for _, item := range items {
		number, ok := aliases[item]
		if !ok {
			parsed, err := strconv.Atoi(item)
			if err != nil {
				return nil, fmt.Errorf("%s contains invalid value %q", name, item)
			}
			number = parsed
		}
		if !valid(number) {
			return nil, fmt.Errorf("%s contains unsupported value %d", name, number)
		}
		result = append(result, number)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("%s must not be empty", name)
	}
	return result, nil
}

func splitNonempty(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
