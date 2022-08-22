package krn

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	wildcard          = "*"
	tokenSeparator    = ":"
	subtokenSeparator = "/"
)

var (
	ErrMalformedKRN         = errors.New("malformed KRN")
	ErrMalformedWildcardKRN = errors.New("malformed wildcard KRN")
)

// KRN is the Kaa Resource Name: a regular or a wildcard one.
//
// The standard string KRN representation is:
//
//	krn:<service>:<tenant ID>:[<pool>]:<resource type>[<resource path>]/<resource ID>
//
// KRN (sub-)tokens consist of latin letters (`a-zA-Z`), digits (`0-9`), dashes (`-`), underscores (`_`), at signs (`@`), and dots (`.`).
// Semicolon (`:`) and slash (`/`) are reserved separators for KRN tokens and subtokens, respectively.
// Asterisk (`*`) is reserved for KRN wildcards.
// There might only be one trailing asterisk in a KRN.
type KRN struct {
	prefixToken  string
	service      string
	tenantID     string
	pool         []string // Can be nil, {"*"}, or {"", ...} (start with an empty string to denote the root pool)
	resourceType string
	resourcePath []string // Can be nil or contain 1 or more sub-tokens. No wildcards allowed.
	resourceID   string
}

// NewKRN constructs a new KRN based on its constituent tokens, which are verified in the process.
//
// Pool and resourcePath slices contents is copied for safety. When pool is non-empty, the first item must be an empty
// string ("") or a wildcard ("*"). resourcePath may not contain wildcards.
//
// One of the returned values is always nil.
func NewKRN(prefixToken, service, tenantID string, pool []string, resourceType string, resourcePath []string, resourceID string) (*KRN, error) {
	res := &KRN{
		prefixToken:  prefixToken,
		service:      service,
		tenantID:     tenantID,
		pool:         copyNonEmptyStringSlice(pool),
		resourceType: resourceType,
		resourcePath: copyNonEmptyStringSlice(resourcePath),
		resourceID:   resourceID,
	}

	switch {
	// Service
	case isWildcardToken(service):
		if err := areTrailingTokensEmpty(tenantID, pool, resourceType, resourcePath, resourceID); err != nil {
			return nil, err
		}

		return res, nil
	case !isValidToken(service):
		return nil, fmt.Errorf("%w: invalid service token", ErrMalformedKRN)

	// Tenant ID
	case isWildcardToken(tenantID):
		if err := areTrailingTokensEmpty("", pool, resourceType, resourcePath, resourceID); err != nil {
			return nil, err
		}

		return res, nil
	case !isValidToken(tenantID):
		return nil, fmt.Errorf("%w: invalid tenant ID token", ErrMalformedKRN)
	}

	// Pool
	for i := range pool {
		switch {
		case isWildcardToken(pool[i]):
			if err := areTrailingTokensEmpty("", pool[i+1:], resourceType, resourcePath, resourceID); err != nil {
				return nil, err
			}

			return res, nil
		case i == 0 && pool[i] != "":
			return nil, fmt.Errorf("%w: invalid pool token 0", ErrMalformedKRN)
		case i > 0 && !isValidToken(pool[i]):
			return nil, fmt.Errorf("%w: invalid pool token %d", ErrMalformedKRN, i)
		}
	}

	switch {
	// Resource type
	case isWildcardToken(resourceType):
		if err := areTrailingTokensEmpty("", nil, "", resourcePath, resourceID); err != nil {
			return nil, err
		}

		return res, nil
	case !isValidToken(resourceType):
		return nil, fmt.Errorf("%w: invalid resource type token", ErrMalformedKRN)
	}

	// Resource path
	for i := range resourcePath {
		switch {
		case isWildcardToken(resourcePath[i]):
			return nil, fmt.Errorf("%w: wildcards not permitted in the resource path", ErrMalformedWildcardKRN)
		case !isValidToken(resourcePath[i]):
			return nil, fmt.Errorf("%w: invalid resource path token %d", ErrMalformedKRN, i)
		}
	}

	switch {
	// Resource ID
	case isWildcardToken(resourceID):
	case !isValidToken(resourceID):
		return nil, fmt.Errorf("%w: invalid resource ID token", ErrMalformedKRN)
	}

	return res, nil
}

// NewKRNFromString constructs a new KRN based on its string representation.
//
// One of the returned values is always nil.
func NewKRNFromString(krn string) (*KRN, error) {
	if krn == wildcard {
		// Special case for blanket wildcard KRNs ("*"), no extra parsing and validation required
		return &KRN{service: wildcard}, nil
	}

	var wildcardKRN bool

	switch strings.Count(krn, wildcard) {
	case 0:
	case 1:
		if asteriskOffset := strings.Index(krn, wildcard); asteriskOffset != len(krn)-1 {
			return nil, fmt.Errorf("%w: misplaced asterisk at index %d", ErrMalformedWildcardKRN, asteriskOffset)
		}

		wildcardKRN = true
	default:
		return nil, fmt.Errorf("%w: only one asterisk allowed", ErrMalformedWildcardKRN)
	}

	krnTokens := strings.Split(krn, tokenSeparator)

	switch {
	case krnTokens[0] == "":
		return nil, fmt.Errorf("%w: empty prefix token", ErrMalformedKRN)
	case len(krnTokens[len(krnTokens)-1]) == 0:
		return nil, fmt.Errorf("%w: last token is empty", ErrMalformedKRN)
	case len(krnTokens) < 5 && !wildcardKRN:
		return nil, fmt.Errorf("%w: too few tokens in a non-wildcard KRN", ErrMalformedKRN)
	}

	var (
		tenantID     string
		pool         []string
		resourceType string
		resourcePath []string
		resourceID   string
	)

	switch len(krnTokens) {
	case 5:
		resourceSubtokens := strings.Split(krnTokens[4], subtokenSeparator)
		switch len(resourceSubtokens) {
		default:
			resourcePath = resourceSubtokens[1 : len(resourceSubtokens)-1]

			fallthrough
		case 2:
			resourceID = resourceSubtokens[len(resourceSubtokens)-1]

			fallthrough
		case 1:
			resourceType = resourceSubtokens[0]
		}

		fallthrough
	case 4:
		if len(krnTokens[3]) > 0 {
			pool = strings.Split(krnTokens[3], subtokenSeparator)
		}

		fallthrough
	case 3:
		tenantID = krnTokens[2]
	case 2:
	case 1:
		return nil, fmt.Errorf("%w: too few tokens", ErrMalformedKRN)
	default:
		return nil, fmt.Errorf("%w: too many tokens", ErrMalformedKRN)
	}

	return NewKRN(krnTokens[0], krnTokens[1], tenantID, pool, resourceType, resourcePath, resourceID)
}

// String returns the human-readable KRN string representation.
//
//	krn:<service>:<tenant ID>:[<pool>]:<resource type>[<resource path>]/<resource ID>
//
// Blanket wildcard KRNs serialize into "*": equivalent to "krn:*", but shorter.
func (k *KRN) String() string {
	if isWildcardToken(k.service) {
		return wildcard
	}

	var res strings.Builder

	res.WriteString(k.prefixToken)
	res.WriteString(tokenSeparator)
	res.WriteString(k.service)
	res.WriteString(tokenSeparator)
	res.WriteString(k.tenantID)

	wildcardComplete := isWildcardToken(k.tenantID)
	if !wildcardComplete {
		res.WriteString(tokenSeparator)

		for i := range k.pool {
			if i > 0 {
				res.WriteString(subtokenSeparator)
			}

			res.WriteString(k.pool[i])

			wildcardComplete = wildcardComplete || isWildcardToken(k.pool[i])
		}
	}

	if !wildcardComplete {
		res.WriteString(tokenSeparator)
		res.WriteString(k.resourceType)

		wildcardComplete = wildcardComplete || isWildcardToken(k.resourceType)
	}

	if !wildcardComplete {
		for i := range k.resourcePath {
			res.WriteString(subtokenSeparator)
			res.WriteString(k.resourcePath[i])

			wildcardComplete = wildcardComplete || isWildcardToken(k.resourcePath[i])
		}
	}

	if !wildcardComplete {
		res.WriteString(subtokenSeparator)
		res.WriteString(k.resourceID)
	}

	return res.String()
}

// GetPrefixToken returns the KRN prefixToken string.
func (k *KRN) GetPrefixToken() string { return k.prefixToken }

// Base64 returns the base64-encoded KRN string representation.
func (k *KRN) Base64() string { return base64.StdEncoding.EncodeToString([]byte(k.String())) }

// MarshalJSON encodes KRN as a JSON string.
func (k *KRN) MarshalJSON() ([]byte, error) { return json.Marshal(k.String()) }

// UnmarshalJSON decodes string-encoded KRN from a JSON string.
func (k *KRN) UnmarshalJSON(data []byte) error {
	var krnString string

	if err := json.Unmarshal(data, &krnString); err != nil {
		return err
	}

	krn, err := NewKRNFromString(krnString)
	if err != nil {
		return err
	}

	*k = *krn

	return nil
}

// IsTenantID returns whether KRN belongs to a given tenant.
func (k *KRN) IsTenantID(tenant string) bool { return k.tenantID == tenant }

// IsWildcard returns whether the KRN is a wildcard one.
func (k *KRN) IsWildcard() bool { return k.resourceID == "" || isWildcardToken(k.resourceID) }

// Matches returns whether the receiver KRN matches k2.
// Both KRNs may be wildcards and true is only returned when k denotes a subset of k2.
func (k *KRN) Matches(k2 *KRN) bool {
	k2string := k2.String()

	if k2.IsWildcard() {
		return strings.HasPrefix(k.String(), k2string[:len(k2string)-1])
	}

	return k2string == k.String()
}

// MatchingKRNs returns string representations of all wildcard and plain KRNs that match a given KRN.
func (k *KRN) MatchingKRNs() []string {
	krn := k.String()

	var res []string // Preallocate space depending on whether the KRN is a wildcard (non-wildcard requires one extra item for the KRN itself)
	if k.IsWildcard() {
		res = make([]string, 0, strings.Count(krn, tokenSeparator)+strings.Count(krn, subtokenSeparator))
	} else {
		res = append(make([]string, 0, strings.Count(krn, tokenSeparator)+strings.Count(krn, subtokenSeparator)+1), krn)
	}

	// Cut KRN from the right up to the last : or / separator until only "krn" prefix remains
	for i := strings.LastIndexAny(krn, tokenSeparator+subtokenSeparator); i > len(k.prefixToken); i = strings.LastIndexAny(krn, tokenSeparator+subtokenSeparator) {
		res = append(res, krn[:i+1]+wildcard)
		krn = krn[:i]
	}

	return append(res, wildcard)
}

/*
 * Internal functions
 */

func isWildcardToken(token string) bool { return token == wildcard }

func isValidToken(token string) bool {
	if len(token) == 0 {
		return false
	}

	for _, c := range token {
		if !isAllowedTokenRune(c) {
			return false
		}
	}

	return true
}

func isAllowedTokenRune(c rune) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9') ||
		c == '-' || c == '_' || c == '@' || c == '.' || c == '+'
}

func copyNonEmptyStringSlice(s []string) []string {
	if len(s) == 0 {
		return nil
	}

	res := make([]string, len(s))
	copy(res, s)

	return res
}

// areTrailingTokensEmpty is used to verify that trailing tokens in a wildcard KRN are all empty.
// Only pass those tokens which require validation.
func areTrailingTokensEmpty(tenantID string, pool []string, resourceType string, resourcePath []string, resourceID string) error {
	switch {
	case len(tenantID) > 0:
		return fmt.Errorf("%w: tenant ID is not empty", ErrMalformedWildcardKRN)
	case len(pool) > 0:
		return fmt.Errorf("%w: pool is not empty", ErrMalformedWildcardKRN)
	case len(resourceType) > 0:
		return fmt.Errorf("%w: resource type is not empty", ErrMalformedWildcardKRN)
	case len(resourcePath) > 0:
		return fmt.Errorf("%w: resource path is not empty", ErrMalformedWildcardKRN)
	case len(resourceID) > 0:
		return fmt.Errorf("%w: resource ID is not empty", ErrMalformedWildcardKRN)
	}

	return nil
}
