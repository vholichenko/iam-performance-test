package action

import (
	"encoding/json"
	"errors"
	"strings"
)

// Action represents a possible resource operation within a service.
// A principal must be allowed the action to perform the associated operation.
//
// Valid action format is as follows:
//  <service name>:<resource type>[:<operation target resource type>]:<operation>
//
// • Service name is the short name of the resource service that handles the action, e.g. "iam", "kpc", etc.
//
// • Resource type is the resource type associated with the action.
// You grant action against a resource of this type.
// Some examples are: "user", "group", "endpoint", etc.
//
// • Operation targer resource type is an optional token that identifies the type of resource impacted by the action.
// This is useful when action is granted against a resource different from the impacted.
// Consider "iam:group:user:add" action that permits adding users to a group.
// This action is granted against a group, but targets users.
//
// • Operation determines the type of activity regulated by the action.
// Typical operations are: "create", "read", "update", "delete", etc.
//
// Example actions:
//  iam:user:read
//  iam:group:create
//  iam:group:user:add
//  iam:policy:update
//
// Actions also support wildcards.
// An action wildcard is the one that terminates with an asterisk ("*").
// The asterisk must immediately follow the action token delimiter (":") except in a blanket wildcard action "*", which only has one character.
//
// Example action wildcards:
//  *
//  iam:*
//  iam:user:*
//  iam:group:*
//  iam:group:user:*
//
// Action wildcards match any actions that have an identical prefix (up to the asterisk).
//
// Action is declared as a string type for convenience so that you can declare actions as constants:
//  const userReadAction Action = "iam:user:read"
// While you can, technically, declare a malformed Action, it will not be useful for any purpose.
type Action string

// Any action is a blanket wildcard that matches any valid action.
const Any Action = "*"

const (
	delimiter = ':'
	wildcard  = '*'
)

func (a Action) MatchingActionsString() []string {
	if !a.IsValid() {
		return nil
	}

	var res []string // Preallocate space depending on whether the Action is a wildcard (non-wildcard requires one extra item for the Action itself)
	if a[len(a)-1] == wildcard {
		res = make([]string, 0, strings.Count(string(a), string(delimiter))+1)
	} else {
		res = append(make([]string, 0, strings.Count(string(a), string(delimiter))+2), string(a))
	}

	// Cut Action from the right up to the last : delimiter until no delimiters remain
	for i := strings.LastIndex(string(a), string(delimiter)); i >= 0; i = strings.LastIndex(string(a), string(delimiter)) {
		res = append(res, string(a)[:i+1]+string(wildcard))
		a = a[:i]
	}

	return append(res, "*")
}

// IsValid returns whether an Action is well-formed.
func (a Action) IsValid() bool {
	if len(a) == 0 {
		return false
	}

	const minDelimiters, maxDelimiters = 1, 3 // One to three ':' delimiters allowed in an Action except the blanket wildcard

	delimiters, lastDelimiter := 0, true

	for i := range a {
		switch a[i] {
		case 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '-':
			lastDelimiter = false
		case delimiter:
			delimiters++
			if lastDelimiter || delimiters > maxDelimiters {
				return false
			}

			lastDelimiter = true
		case wildcard:
			if i < len(a)-1 || !lastDelimiter {
				// Wildcard is only allowed in the end and following a delimiter, except in the blanket action wildcard "*"
				return false
			}

			return true
		default:
			return false
		}
	}

	return !lastDelimiter && delimiters > minDelimiters
}

// IsWildcard returns whether the Action is a valid wildcard.
func (a Action) IsWildcard() bool { return a.IsValid() && a[len(a)-1] == wildcard }

// Matches returns true when both a and a2 are valid and a matches a2. Otherwise it returns false.
func (a Action) Matches(a2 Action) bool {
	if !a.IsValid() || !a2.IsValid() {
		return false
	}

	if a2[len(a2)-1] == wildcard {
		return strings.HasPrefix(string(a), string(a2)[:len(a2)-1])
	}

	return a == a2
}

// MatchingActions returns all wildcard and plain Actions that match a given valid Action.
// If a is not a valid action, the function returns nil.
func (a Action) MatchingActions() []Action {
	if !a.IsValid() {
		return nil
	}

	var res []Action // Preallocate space depending on whether the Action is a wildcard (non-wildcard requires one extra item for the Action itself)
	if a[len(a)-1] == wildcard {
		res = make([]Action, 0, strings.Count(string(a), string(delimiter))+1)
	} else {
		res = append(make([]Action, 0, strings.Count(string(a), string(delimiter))+2), a)
	}

	// Cut Action from the right up to the last : delimiter until no delimiters remain
	for i := strings.LastIndex(string(a), string(delimiter)); i >= 0; i = strings.LastIndex(string(a), string(delimiter)) {
		res = append(res, Action(string(a)[:i+1]+string(wildcard)))
		a = a[:i]
	}

	return append(res, Any)
}

// UnmarshalJSON decodes Action from a JSON string.
func (a *Action) UnmarshalJSON(data []byte) error {
	var actionString string

	if err := json.Unmarshal(data, &actionString); err != nil {
		return err
	}

	if *a = Action(actionString); !a.IsValid() {
		return errors.New("invalid action")
	}

	return nil
}

// String returns the human-readable Action string representation.
func (a *Action) String() string { return string(*a) }
