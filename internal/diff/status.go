package diff

import (
	"encoding/json"
	"errors"
)

// schemaIntegerStatus implements JSON Schema draft 2020-12 integer semantics:
// 200, 200.0 and 2e2 are the same integral value. encoding/json's decoder
// into Go int rejects the latter two even though the published schema accepts
// them. Parse decimal digits exactly; float64 would round subtle fractions.
// Work and memory are bounded by the already enforced 4 MiB input limit.
type schemaIntegerStatus int

func (s *schemaIntegerStatus) UnmarshalJSON(raw []byte) error {
	if len(raw) == 0 || raw[0] < '0' || raw[0] > '9' || !json.Valid(raw) {
		return errors.New("HTTP status must be a JSON integer between 100 and 599")
	}
	// JSON forbids a leading plus. Only a nonnegative value in 100..599 is
	// relevant, therefore a leading minus is immediately invalid.
	var digits []byte
	// len(raw) <= 4 MiB. Preserve up to that many significant digits without
	// arbitrary precision arithmetic that could allocate huge exponent powers.
	digits = make([]byte, 0, len(raw))
	integerDigits := 0
	i := 0
	inFraction := false
	for i < len(raw) && raw[i] != 'e' && raw[i] != 'E' {
		c := raw[i]
		if c == '.' {
			inFraction = true
		} else {
			digits = append(digits, c)
			if !inFraction {
				integerDigits++
			}
		}
		i++
	}
	exponent := 0
	if i < len(raw) {
		i++
		sign := 1
		if i < len(raw) && (raw[i] == '+' || raw[i] == '-') {
			if raw[i] == '-' {
				sign = -1
			}
			i++
		}
		// A huge exponent cannot be cancelled by at most len(raw) digits;
		// saturating it prevents integer overflow while preserving verdicts.
		capExp := len(raw) + 8
		for ; i < len(raw); i++ {
			d := int(raw[i] - '0')
			if exponent > (capExp-d)/10 {
				exponent = capExp
			} else if exponent < capExp {
				exponent = exponent*10 + d
			}
		}
		exponent *= sign
	}
	first := 0
	for first < len(digits) && digits[first] == '0' {
		first++
	}
	if first == len(digits) {
		return errors.New("HTTP status outside 100..599")
	}
	significantIntegerDigits := integerDigits + exponent - first
	if significantIntegerDigits != 3 {
		return errors.New("HTTP status outside 100..599")
	}
	value := 0
	for j := 0; j < 3; j++ {
		d := byte('0')
		if first+j < len(digits) {
			d = digits[first+j]
		}
		value = value*10 + int(d-'0')
	}
	// A nonzero fractional tail must never be truncated or rounded.
	for j := first + 3; j < len(digits); j++ {
		if digits[j] != '0' {
			return errors.New("HTTP status has fractional part")
		}
	}
	if value < 100 || value > 599 {
		return errors.New("HTTP status outside 100..599")
	}
	*s = schemaIntegerStatus(value)
	return nil
}
