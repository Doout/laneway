package main

import (
	"strconv"
	"strings"
)

func compareStableVersions(left, right string) (int, bool) {
	parse := func(value string) ([3]uint64, bool) {
		var result [3]uint64
		parts := strings.Split(value, ".")
		if len(parts) != len(result) {
			return result, false
		}
		for index, part := range parts {
			if part == "" || (len(part) > 1 && part[0] == '0') {
				return result, false
			}
			number, err := strconv.ParseUint(part, 10, 64)
			if err != nil {
				return result, false
			}
			result[index] = number
		}
		return result, true
	}
	leftParts, leftOK := parse(left)
	rightParts, rightOK := parse(right)
	if !leftOK || !rightOK {
		return 0, false
	}
	for index := range leftParts {
		if leftParts[index] < rightParts[index] {
			return -1, true
		}
		if leftParts[index] > rightParts[index] {
			return 1, true
		}
	}
	return 0, true
}
