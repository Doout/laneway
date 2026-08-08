// Package nftstate validates nftables tables before a new Laneway process
// removes state left by a crashed predecessor.
package nftstate

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Chain describes one chain in a generated Laneway table. Base is false for
// the regular ownership chain and true for hook-bearing base chains.
type Chain struct {
	Name     string
	Type     string
	Hook     string
	Policy   string
	Priority int
	Base     bool
}

// Rule describes one non-ownership rule in a generated Laneway table.
type Rule struct {
	Chain   string
	Comment string
	Expr    []any
}

// Shape is the complete nftables shape that may be reclaimed after a crash.
// Validation is deliberately exact: unknown tables, chains, rules, fields,
// expressions, or comments make the table foreign.
type Shape struct {
	Family        string
	Table         string
	OwnerChain    string
	Marker        string
	SessionPrefix string
	Chains        []Chain
	Rules         []Rule
}

// Marker returns a deterministic ownership marker bound to a ruleset schema
// and all configuration fields that determine its kernel effects.
func Marker(role string, fields ...string) string {
	h := sha256.New()
	_, _ = h.Write([]byte("laneway-nft-state-v1\x00" + role))
	for _, field := range fields {
		_, _ = h.Write([]byte{'\x00'})
		_, _ = h.Write([]byte(field))
	}
	return "laneway-" + role + "-v1-" + hex.EncodeToString(h.Sum(nil))
}

// MatchMeta builds the JSON expression emitted by nft for an interface match.
func MatchMeta(key, value string) any {
	return map[string]any{"match": map[string]any{
		"op": "==", "left": map[string]any{"meta": map[string]any{"key": key}}, "right": value,
	}}
}

// MatchPrefix builds the JSON expression emitted by nft for an address-prefix
// payload match.
func MatchPrefix(protocol, field, address string, bits int) any {
	return map[string]any{"match": map[string]any{
		"op":    "==",
		"left":  map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}},
		"right": map[string]any{"prefix": map[string]any{"addr": address, "len": bits}},
	}}
}

// MatchAddressPrefix matches nft's JSON normalization: host prefixes are
// emitted as scalar addresses while shorter prefixes retain a prefix object.
func MatchAddressPrefix(protocol, field, address string, bits, addressBits int) any {
	right := any(map[string]any{"prefix": map[string]any{"addr": address, "len": bits}})
	if bits == addressBits {
		right = address
	}
	return map[string]any{"match": map[string]any{
		"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}, "right": right,
	}}
}

func MatchPayload(protocol, field string, right any) any {
	return map[string]any{"match": map[string]any{
		"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": protocol, "field": field}}, "right": right,
	}}
}

func Range(first, last uint16) any { return map[string]any{"range": []any{int(first), int(last)}} }

// MatchCTStates builds the JSON expression emitted by nft for a conntrack
// state-set match.
func MatchCTStates(states ...string) any {
	values := make([]any, len(states))
	for i, state := range states {
		values[i] = state
	}
	return map[string]any{"match": map[string]any{
		"op": "in", "left": map[string]any{"ct": map[string]any{"key": "state"}}, "right": values,
	}}
}

func Accept() any            { return map[string]any{"accept": nil} }
func Drop() any              { return map[string]any{"drop": nil} }
func Jump(target string) any { return map[string]any{"jump": map[string]any{"target": target}} }
func Masquerade() any        { return map[string]any{"masquerade": nil} }

// Validate verifies a JSON `nft -j list table` response and returns the opaque
// session-state comment. Callers must validate that state before deletion.
func Validate(raw []byte, shape Shape) (string, error) {
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var document struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if err := decoder.Decode(&document); err != nil {
		return "", fmt.Errorf("decode nftables JSON: %w", err)
	}
	if len(document.NFTables) == 0 {
		return "", errors.New("empty nftables document")
	}

	var tables, chains, rules []map[string]any
	for _, object := range document.NFTables {
		if len(object) != 1 {
			return "", errors.New("nftables object has unexpected fields")
		}
		for kind, value := range object {
			if kind == "metainfo" {
				continue
			}
			entity, ok := value.(map[string]any)
			if !ok {
				return "", fmt.Errorf("nftables %s is not an object", kind)
			}
			switch kind {
			case "table":
				tables = append(tables, entity)
			case "chain":
				chains = append(chains, entity)
			case "rule":
				rules = append(rules, entity)
			default:
				return "", fmt.Errorf("unexpected nftables object %q", kind)
			}
		}
	}
	if len(tables) != 1 || !exactKeys(tables[0], "family", "name", "handle") ||
		stringValue(tables[0]["family"]) != shape.Family || stringValue(tables[0]["name"]) != shape.Table {
		return "", errors.New("table identity or shape differs")
	}

	expectedChains := make(map[string]Chain, len(shape.Chains))
	for _, chain := range shape.Chains {
		if _, duplicate := expectedChains[chain.Name]; duplicate {
			return "", fmt.Errorf("duplicate expected chain %q", chain.Name)
		}
		expectedChains[chain.Name] = chain
	}
	if len(chains) != len(expectedChains) {
		return "", fmt.Errorf("chain count %d differs from %d", len(chains), len(expectedChains))
	}
	for _, actual := range chains {
		name := stringValue(actual["name"])
		expected, ok := expectedChains[name]
		if !ok || stringValue(actual["family"]) != shape.Family || stringValue(actual["table"]) != shape.Table {
			return "", fmt.Errorf("unexpected chain %q", name)
		}
		if expected.Base {
			if !exactKeys(actual, "family", "table", "name", "handle", "type", "hook", "prio", "policy") ||
				stringValue(actual["type"]) != expected.Type || stringValue(actual["hook"]) != expected.Hook ||
				stringValue(actual["policy"]) != expected.Policy || intValue(actual["prio"]) != expected.Priority {
				return "", fmt.Errorf("base chain %q differs", name)
			}
		} else if !exactKeys(actual, "family", "table", "name", "handle") {
			return "", fmt.Errorf("regular chain %q differs", name)
		}
	}

	actualByChain := make(map[string][]map[string]any)
	for _, rule := range rules {
		if !exactKeys(rule, "family", "table", "chain", "handle", "comment", "expr") ||
			stringValue(rule["family"]) != shape.Family || stringValue(rule["table"]) != shape.Table {
			return "", errors.New("rule identity or shape differs")
		}
		chain := stringValue(rule["chain"])
		if _, ok := expectedChains[chain]; !ok {
			return "", fmt.Errorf("rule uses unexpected chain %q", chain)
		}
		actualByChain[chain] = append(actualByChain[chain], rule)
	}

	ownerRules := actualByChain[shape.OwnerChain]
	if len(ownerRules) != 2 || stringValue(ownerRules[0]["comment"]) != shape.Marker ||
		!counterOnly(ownerRules[0]["expr"]) || !strings.HasPrefix(stringValue(ownerRules[1]["comment"]), shape.SessionPrefix) ||
		!counterOnly(ownerRules[1]["expr"]) {
		return "", errors.New("ownership rules differ")
	}
	session := stringValue(ownerRules[1]["comment"])
	delete(actualByChain, shape.OwnerChain)

	expectedByChain := make(map[string][]Rule)
	for _, rule := range shape.Rules {
		expectedByChain[rule.Chain] = append(expectedByChain[rule.Chain], rule)
	}
	chainNames := make([]string, 0, len(expectedChains))
	for name := range expectedChains {
		if name != shape.OwnerChain {
			chainNames = append(chainNames, name)
		}
	}
	sort.Strings(chainNames)
	for _, chain := range chainNames {
		actual, expected := actualByChain[chain], expectedByChain[chain]
		if len(actual) != len(expected) {
			return "", fmt.Errorf("rule count for chain %q differs", chain)
		}
		for i := range expected {
			if stringValue(actual[i]["comment"]) != expected[i].Comment || !expressionsEqual(actual[i]["expr"], expected[i].Expr) {
				return "", fmt.Errorf("rule %d in chain %q differs", i, chain)
			}
		}
	}
	return session, nil
}

func exactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func intValue(value any) int {
	switch value := value.(type) {
	case json.Number:
		result, _ := value.Int64()
		return int(result)
	case float64:
		return int(value)
	case int:
		return value
	default:
		return 0
	}
}

func counterOnly(value any) bool {
	expressions, ok := value.([]any)
	if !ok || len(expressions) != 1 {
		return false
	}
	expression, ok := expressions[0].(map[string]any)
	if !ok || !exactKeys(expression, "counter") {
		return false
	}
	counter, ok := expression["counter"].(map[string]any)
	return ok && exactKeys(counter, "packets", "bytes")
}

func expressionsEqual(actual any, expected []any) bool {
	actualExpressions, ok := actual.([]any)
	if !ok {
		return false
	}
	// Round-tripping expected expressions through JSON gives them the same
	// json.Number representation used by the decoder above.
	encoded, err := json.Marshal(expected)
	if err != nil {
		return false
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.UseNumber()
	var normalized []any
	if err := decoder.Decode(&normalized); err != nil {
		return false
	}
	return reflect.DeepEqual(actualExpressions, normalized)
}
