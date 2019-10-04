package outputs

import (
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

type influxdbPayload string

func newInfluxdbPayload(falcopayload types.FalcoPayload, config *types.Configuration) influxdbPayload {
	var s string

	s = "events,rule=" + strings.Replace(falcopayload.Rule, " ", "_", -1) + ",priority=" + strings.Replace(falcopayload.Priority, " ", "_", -1)

	falcopayload.OutputFieldStrings(func(k, v string) {
		s += "," + k + "=" + strings.Replace(v, " ", "_", -1)
	})

	s += " value=\"" + falcopayload.Output + "\""

	return influxdbPayload(s)
}

// InfluxdbPost posts event to InfluxDB
func (c *Client) InfluxdbPost(falcopayload types.FalcoPayload) {
	err := c.Post(newInfluxdbPayload(falcopayload, c.Config))
	if err != nil {
		c.Stats.Influxdb.Add("error", 1)
	} else {
		c.Stats.Influxdb.Add("sent", 1)
	}
	c.Stats.Influxdb.Add("total", 1)
}
