package outputs

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"
)

var falcoTestInput = `{"output":"This is a test from falcosidekick","priority":"Debug","rule":"Test rule", "time":"2001-01-01T01:10:00Z","output_fields": {"proc.name":"falcosidekick", "proc.tty": 1234}}`

func TestNewClient(t *testing.T) {
	u, _ := url.Parse("http://localhost")
	config := &types.Configuration{}
	stats := &types.Statistics{}
	testClientOutput := Client{OutputType: "test", EndpointURL: u, Config: config, Stats: stats}
	_, err := NewClient("test", "localhost/%*$¨^!/:;", config, stats)
	if err == nil {
		t.Fatalf("error while creating client object : %v\n", err)
	}
	nc, _ := NewClient("test", "http://localhost", config, stats)
	if !reflect.DeepEqual(&testClientOutput, nc) {
		t.Fatalf("expected: %v, got: %v\n", testClientOutput, nc)
	}
}

func TestPost(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Fatalf("expected method : POST, got %s\n", r.Method)
		}
		switch r.URL.EscapedPath() {
		case "/200":
			w.WriteHeader(http.StatusOK)
		case "/400":
			w.WriteHeader(http.StatusBadRequest)
		case "/401":
			w.WriteHeader(http.StatusUnauthorized)
		case "/403":
			w.WriteHeader(http.StatusForbidden)
		case "/404":
			w.WriteHeader(http.StatusNotFound)
		case "/422":
			w.WriteHeader(http.StatusUnprocessableEntity)
		case "/429":
			w.WriteHeader(http.StatusTooManyRequests)
		case "/502":
			w.WriteHeader(http.StatusBadGateway)
		}
	}))

	nc, _ := NewClient("", "", &types.Configuration{}, &types.Statistics{})

	for i, j := range map[string]error{"/200": nil, "/400": ErrHeaderMissing, "/401": ErrClientAuthenticationError, "/403": ErrForbidden, "/404": ErrNotFound, "/422": ErrUnprocessableEntityError, "/429": ErrTooManyRequest, "/502": errors.New("502 Bad Gateway")} {
		nc, _ = NewClient("", ts.URL+i, &types.Configuration{}, &types.Statistics{})
		err := nc.Post("")
		if !reflect.DeepEqual(err, j) {
			t.Fatalf("expected error: %v, got: %v\n", j, err)
		}
	}
}

// Deep equality for two structs, ignoring the order of slice elements because iteration order of maps in Golang is randomized, so our output arrays can be in any order
func DeepEqualsIgnoreSliceOrder(expected, actual interface{}) bool {
	// If the expected and actual are exactly identical we're done
	if reflect.DeepEqual(expected, actual) {
		return true
	}

	// If either value isn't a slice, and they're not identical, they're not equal
	if reflect.TypeOf(expected).Kind() != reflect.Slice ||
		reflect.TypeOf(actual).Kind() != reflect.Slice {
		return false
	}

	expectedValue := reflect.ValueOf(expected)
	actualValue := reflect.ValueOf(actual)
	if expectedValue.Len() != actualValue.Len() {
		return false
	}

	// If both slices have the same number of occurences of each element using our definition of equality (ignoring slice order)
	// and they have the same length, they have the same contents. We need to check the number of occurences and not just that an element
	// exists to avoid a case like ["a", "b", "b" ] == ["a", "a", "b"].
	// This could be more efficient if we memoized occurences for elements we've already seen, but the slices we're comparing are very small
	for i := 0; i < expectedValue.Len(); i++ {
		if occurencesOfElement(expectedValue.Index(i), expectedValue) != occurencesOfElement(actualValue.Index(i), actualValue) {
			return false
		}
	}
	return true
}

func occurencesOfElement(element, slice reflect.Value) int {
	occurences := 0
	for i := 0; i < slice.Len(); i++ {
		if DeepEqualsIgnoreSliceOrder(element, slice.Index(i)) {
			occurences += 1
		}
	}
	return occurences
}
