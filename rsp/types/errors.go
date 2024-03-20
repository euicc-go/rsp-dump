package types

import "encoding/json"

type Error StatusCodeData

func (e *Error) Error() string {
	return e.Message
}

func (e *Error) MarshalJSON() ([]byte, error) {
	data := StatusCodeData{Status: ExecutedSuccess}
	if e != nil {
		data = StatusCodeData(*e)
	}
	if e.Status == "" {
		data.Status = Failed
	}
	status := FunctionExecutionStatus{StatusCodeData: &data}
	header := Header{FunctionExecutionStatus: status}
	return json.Marshal(&GeneralResponse{Header: header})
}
