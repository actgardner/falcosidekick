package outputs

import (
	"strings"

	"github.com/falcosecurity/falcosidekick/types"
)

const (
	// AlertmanagerURI is default endpoint where to send events
	AlertmanagerURI string = "/api/v1/alerts"
)

type alertmanagerPayload struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func newAlertmanagerPayload(falcopayload types.FalcoPayload) []alertmanagerPayload {
	var amPayload alertmanagerPayload
	amPayload.Labels = make(map[string]string)
	amPayload.Annotations = make(map[string]string)

	falcopayload.OutputFieldStrings(func(k, v string) {
		//AlertManger doesn't support dots in a label name
		amPayload.Labels[strings.Replace(k, ".", "_", -1)] = v
	})
	amPayload.Labels["source"] = "falco"
	amPayload.Labels["rule"] = falcopayload.Rule

	amPayload.Annotations["info"] = falcopayload.Output
	amPayload.Annotations["summary"] = falcopayload.Rule

	var a []alertmanagerPayload

	a = append(a, amPayload)

	return a
}

// AlertmanagerPost posts event to AlertManager
func (c *Client) AlertmanagerPost(falcopayload types.FalcoPayload) {
	err := c.Post(newAlertmanagerPayload(falcopayload))
	if err != nil {
		c.Stats.Alertmanager.Add("error", 1)
	} else {
		c.Stats.Alertmanager.Add("sent", 1)
	}
	c.Stats.Alertmanager.Add("total", 1)
}
