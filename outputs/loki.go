package outputs

import (
	"github.com/falcosecurity/falcosidekick/types"
	"strings"
	"time"
)

type lokiPayload struct {
	Streams []lokiStream `json:"streams"`
}

type lokiStream struct {
	Labels  string      `json:"labels"`
	Entries []lokiEntry `json:"entries"`
}

type lokiEntry struct {
	Ts   string `json:"ts"`
	Line string `json:"line"`
}

func newLokiPayload(falcopayload types.FalcoPayload, config *types.Configuration) lokiPayload {

	le := lokiEntry{Ts: falcopayload.Time.Format(time.RFC3339), Line: falcopayload.Output}
	ls := lokiStream{Entries: []lokiEntry{le}}

	var s string
	falcopayload.OutputFieldStrings(func(k, v string) {
		s += strings.Replace(strings.Replace(strings.Replace(k, ".", "", -1), "]", "", -1), "[", "", -1) + "=\"" + v + "\","
	})
	s += "rule=\"" + falcopayload.Rule + "\","
	s += "priority=\"" + falcopayload.Priority + "\","

	ls.Labels = "{" + s[:len(s)-1] + "}"

	return lokiPayload{Streams: []lokiStream{ls}}
}

// LokiPost posts event to Loki
func (c *Client) LokiPost(falcopayload types.FalcoPayload) {
	err := c.Post(newLokiPayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Loki.Add("error", 1)
	} else {
		c.Stats.Loki.Add("sent", 1)
	}
	c.Stats.Loki.Add("total", 1)
}
