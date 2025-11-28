package dump

import "errors"

var (
	ErrNotFound = errors.New("rsp-dump: no supported RSP server found")
)
