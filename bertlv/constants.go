package bertlv

type Class byte

const (
	Universal       Class = 0b00
	Application     Class = 0b01
	ContextSpecific Class = 0b10
	Private         Class = 0b11
)
