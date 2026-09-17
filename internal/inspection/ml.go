package inspection

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/kltngfw/ngfw/internal/domain"
)

type MLClient struct {
	Endpoint string
	Client   *http.Client
	MaxInput int
}

func NewMLClient(endpoint string, timeout time.Duration) *MLClient {
	if timeout <= 0 {
		timeout = 200 * time.Millisecond
	}
	return &MLClient{Endpoint: endpoint, Client: &http.Client{Timeout: timeout}, MaxInput: 64 * 1024}
}
func (c *MLClient) Classify(ctx context.Context, input string) (domain.MLContext, error) {
	if c.Endpoint == "" {
		return domain.MLContext{Available: false}, errors.New("ML endpoint is not configured")
	}
	if len(input) > c.MaxInput {
		input = input[:c.MaxInput]
	}
	body, _ := json.Marshal(map[string]string{"text": input})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/classify", bytes.NewReader(body))
	if err != nil {
		return domain.MLContext{Available: false}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Client.Do(req)
	if err != nil {
		return domain.MLContext{Available: false}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return domain.MLContext{Available: false}, fmt.Errorf("ML returned %s", resp.Status)
	}
	var result struct {
		Class         string             `json:"class"`
		Confidence    float64            `json:"confidence"`
		Probabilities map[string]float64 `json:"probabilities"`
		ModelVersion  string             `json:"model_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return domain.MLContext{Available: false}, err
	}
	return domain.MLContext{PredictedClass: result.Class, Confidence: result.Confidence, Probabilities: result.Probabilities, ModelVersion: result.ModelVersion, Available: true}, nil
}
