package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
}

type ClientIngestOptions struct {
	PolicyPath    string
	PolicyStore   string
	SessionStore  string
	GrantStore    string
	DeliveryStore string
	AuditPath     string
	AuthToken     string
	AirlockPolicy string
	AirlockStore  string
	NoAirlock     bool
}

func NewClient(baseURL string) Client {
	return Client{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

func (c Client) Ingest(ctx context.Context, data []byte, opts ClientIngestOptions) (IngestResult, error) {
	endpoint, err := url.Parse(c.BaseURL + "/ingest")
	if err != nil {
		return IngestResult{}, err
	}
	query := endpoint.Query()
	addQuery(query, "policy", opts.PolicyPath)
	addQuery(query, "policy-store", opts.PolicyStore)
	addQuery(query, "session-store", opts.SessionStore)
	addQuery(query, "grants", opts.GrantStore)
	addQuery(query, "delivery-store", opts.DeliveryStore)
	addQuery(query, "audit", opts.AuditPath)
	addQuery(query, "airlock-policy", opts.AirlockPolicy)
	addQuery(query, "airlock-store", opts.AirlockStore)
	if opts.NoAirlock {
		query.Set("no_airlock", "true")
	}
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return IngestResult{}, err
	}
	req.Header.Set("content-type", "application/json")
	if opts.AuthToken != "" {
		req.Header.Set("authorization", "Bearer "+opts.AuthToken)
	}
	httpClient := c.HTTP
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	res, err := httpClient.Do(req)
	if err != nil {
		return IngestResult{}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		return IngestResult{}, err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return IngestResult{}, fmt.Errorf("daemon ingest failed: status=%d body=%s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	var result IngestResult
	if err := json.Unmarshal(body, &result); err != nil {
		return IngestResult{}, err
	}
	return result, nil
}

func addQuery(query url.Values, key, value string) {
	if value != "" {
		query.Set(key, value)
	}
}
