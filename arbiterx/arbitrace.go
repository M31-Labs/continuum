package arbiterx

type Step struct {
	Rule    string `json:"rule,omitempty"`
	Result  string `json:"result,omitempty"`
	Message string `json:"message,omitempty"`
}
