package outputs

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/falcosecurity/falcosidekick/types"
)

func TestNewInfluxdbPayload(t *testing.T) {
	expectedOutput := `"events,rule=Test_rule,priority=Debug,proc.name=falcosidekick,proc.tty=1234 value=\"This is a test from falcosidekick\""`

	var f types.FalcoPayload
	json.Unmarshal([]byte(falcoTestInput), &f)
	influxdbPayload, _ := json.Marshal(newInfluxdbPayload(f, &types.Configuration{}))

	payloadTags := strings.Split(strings.Split(string(influxdbPayload), " ")[0], ",")
	expectedTags := strings.Split(strings.Split(expectedOutput, " ")[0], ",")
	if !DeepEqualsIgnoreSliceOrder(payloadTags, expectedTags) {
		t.Fatalf("\nexpected tags: \n%v\ngot: \n%v\n", expectedTags, payloadTags)
	}

	payloadValue := strings.Split(string(influxdbPayload), " ")[1]
	expectedValue := strings.Split(expectedOutput, " ")[1]
	if payloadValue != expectedValue {
		t.Fatalf("\nexpected value: \n%v\ngot: \n%v\n", expectedValue, payloadValue)
	}
}
