package outputs

import (
	"encoding/json"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewDatadogPayload(t *testing.T) {
	expectedOutput := `{"title":"Test rule","text":"This is a test from falcosidekick","alert_type":"info","source_type_name":"falco","tags":["proc.name:falcosidekick","proc.tty:1234"]}`

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	s, _ := json.Marshal(newDatadogPayload(f))

	var o1, o2 datadogPayload
	json.Unmarshal([]byte(expectedOutput), &o1)
	json.Unmarshal([]byte(s), &o2)

	if !DeepEqualsIgnoreSliceOrder(o1, o2) {
		// t.Fatalf("\nexpected payload: \n%v\ngot: \n%v\n", o1, o2)
		t.Fatalf("\nexpected payload: \n%v\ngot: \n%v\n", expectedOutput, string(s))
	}
}
