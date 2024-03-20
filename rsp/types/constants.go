package types

type Status string

const (
	ExecutedSuccess     Status = "Executed-Success"
	ExecutedWithWarning Status = "Executed-WithWarning"
	Failed              Status = "Failed"
	Expired             Status = "Expired"
)

func (s Status) Header(err error) Header {
	data := &StatusCodeData{
		Status:      s,
		SubjectCode: "1.1",
		ReasonCode:  "1.1",
		Message:     err.Error(),
	}
	status := FunctionExecutionStatus{StatusCodeData: data}
	return Header{FunctionExecutionStatus: status}
}
