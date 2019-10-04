package types

import (
	"expvar"
	"fmt"
	"strconv"
	"time"
)

// FalcoPayload is a struct to map falco event json
type FalcoPayload struct {
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         time.Time              `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
}

// OutputFieldStrings iterates over the OutputFields and calls it with the string representation of each key and value
func (f *FalcoPayload) OutputFieldStrings(it func(key, value string)) {
	for key, value := range f.OutputFields {
		switch v := value.(type) {
		case string:
			it(key, v)
		case float64:
			it(key, strconv.FormatFloat(v, 'f', -1, 64))
		case bool:
			it(key, strconv.FormatBool(v))
		default:
			it(key, fmt.Sprintf("%v", v))
		}
	}
}

// Configuration is a struct to store configuration
type Configuration struct {
	ListenPort    int
	Debug         bool
	Slack         slackOutputConfig
	Teams         teamsOutputConfig
	Datadog       datadogOutputConfig
	Alertmanager  alertmanagerOutputConfig
	Elasticsearch elasticsearchOutputConfig
	Influxdb      influxdbOutputConfig
	Loki          lokiOutputConfig
	Nats          natsOutputConfig
	AWS           awsOutputConfig
	SMTP          smtpOutputConfig
	Opsgenie      opsgenieOutputConfig
	Customfields  map[string]string
}

type slackOutputConfig struct {
	WebhookURL      string
	Footer          string
	Icon            string
	OutputFormat    string
	MinimumPriority string
}

type teamsOutputConfig struct {
	WebhookURL      string
	ActivityImage   string
	OutputFormat    string
	MinimumPriority string
}

type datadogOutputConfig struct {
	APIKey          string
	MinimumPriority string
}

type alertmanagerOutputConfig struct {
	HostPort        string
	MinimumPriority string
}

type elasticsearchOutputConfig struct {
	HostPort        string
	Index           string
	Type            string
	MinimumPriority string
	Suffix          string
}

type influxdbOutputConfig struct {
	HostPort        string
	Database        string
	User            string
	Password        string
	MinimumPriority string
}

type lokiOutputConfig struct {
	HostPort        string
	MinimumPriority string
}

type natsOutputConfig struct {
	HostPort        string
	MinimumPriority string
}

type awsOutputConfig struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	Lambda          awsLambdaConfig
	SQS             awsSQSConfig
}

type awsLambdaConfig struct {
	FunctionName    string
	InvocationType  string
	LogType         string
	MinimumPriority string
}

type awsSQSConfig struct {
	URL             string
	MinimumPriority string
}

type smtpOutputConfig struct {
	HostPort        string
	User            string
	Password        string
	From            string
	To              string
	OutputFormat    string
	MinimumPriority string
}

type opsgenieOutputConfig struct {
	Region          string
	APIKey          string
	MinimumPriority string
}

// Statistics is a struct to store stastics
type Statistics struct {
	Requests      *expvar.Map
	Slack         *expvar.Map
	Teams         *expvar.Map
	Datadog       *expvar.Map
	Alertmanager  *expvar.Map
	Elasticsearch *expvar.Map
	Loki          *expvar.Map
	Nats          *expvar.Map
	Influxdb      *expvar.Map
	AWSLambda     *expvar.Map
	AWSSQS        *expvar.Map
	SMTP          *expvar.Map
	Opsgenie      *expvar.Map
}
