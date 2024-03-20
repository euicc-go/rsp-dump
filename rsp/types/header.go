package types

import "encoding/json"

type Header struct {
	FunctionExecutionStatus FunctionExecutionStatus `json:"functionExecutionStatus"`
}

type FunctionExecutionStatus struct {
	StatusCodeData *StatusCodeData `json:"statusCodeData"`
}

type StatusCodeData struct {
	Status            Status `json:"status,omitempty"`
	SubjectCode       string `json:"subjectCode"`
	SubjectIdentifier string `json:"subjectIdentifier,omitempty"`
	ReasonCode        string `json:"reasonCode"`
	Message           string `json:"message,omitempty"`
}

func (d *StatusCodeData) MarshalJSON() ([]byte, error) {
	if d == nil {
		return json.Marshal(Error{Status: ExecutedSuccess})
	}
	return json.Marshal(Error(*d))
}
