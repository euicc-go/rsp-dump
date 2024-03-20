package bertlv

import (
	"encoding/hex"
	"github.com/pkg/errors"
)

type Tag []byte

func (t *Tag) UnmarshalBinary(b []byte) (err error) {
	if b[0]&0x1F != 0x1F {
		*t = b[0:1]
		return nil
	}
	if len(b) < 2 {
		return errors.New("indicated tag encoding with with more than one byte, but following bytes are missing")
	}
	if b[1]&0x80 != 0x80 {
		*t = b[0:2]
		return nil
	}
	if len(b) < 3 {
		return errors.New("indicated tag encoding with three bytes, but following bytes are missing")
	}
	*t = b[0:3]
	return nil
}

func (t *Tag) MarshalBinary() ([]byte, error) {
	return *t, nil
}

func (t *Tag) Err() error {
	tag := *t
	if len(tag) > 3 {
		return errors.Errorf("tags must consist of a maximum of three bytes, got %d", len(tag))
	}
	if len(tag) == 1 {
		if tag[0]&0x1F == 0x1F {
			return errors.New("tag consists of one byte but indicates that more bytes follow")
		}
		return nil
	}
	if tag[0]&0x1F != 0x1F {
		return errors.Errorf("tag consists of %d byte but first byte does not indicate that more bytes follow", len(tag))
	}
	if len(tag) == 2 {
		if tag[1]&0x80 == 0x80 {
			return errors.New("tag consists of 2 byte but indicates that more bytes follow")
		}
	} else {
		if tag[1]&0x80 != 0x80 {
			return errors.New("tag consists of 3 byte but second byte does not indicate that more bytes follow")
		}
	}
	return nil
}

func (t *Tag) Primitive() bool {
	return (*t)[0]>>5&0b1 == 0b0
}

func (t *Tag) Constructed() bool {
	return (*t)[0]>>5&0b1 == 0b1
}

func (t *Tag) Class() Class {
	return Class((*t)[0] >> 6)
}

func (t *Tag) String() string {
	return hex.EncodeToString(*t)
}
