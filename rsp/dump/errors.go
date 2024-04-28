package dump

import "errors"

var (
	errNotFound = errors.New("rsp-dump: no supported RSP server found")
)
