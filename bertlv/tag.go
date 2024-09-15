package bertlv

import (
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"math/bits"
)

type Tag []byte

func NewTag(class Class, form Form, value uint64) Tag {
	mask := byte(class)<<6 | byte(form)<<5
	if value < 0x1f {
		return Tag{mask ^ byte(value)}
	}
	tag := Tag{mask ^ 0x1f}
	for index := bits.Len64(value) / 7; index >= 0; index-- {
		if mask = byte((value >> (7 * index)) & 0x7f); index > 0 {
			mask |= 0x80
		}
		tag = append(tag, mask)
	}
	return tag
}

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
	switch t.Class() {
	case Universal:
		return fmt.Sprintf("[Universal %d]", t.Value())
	case Application:
		return fmt.Sprintf("[Application %d]", t.Value())
	case ContextSpecific:
		return fmt.Sprintf("[%d]", t.Value())
	case Private:
		return fmt.Sprintf("[Private %d]", t.Value())
	}
	return hex.EncodeToString(*t)
}

func (t *Tag) Value() (value uint64) {
	tag := *t
	if value = uint64(tag[0] & 0x1f); value != 0x1f {
		return
	}
	index := 1
	for value = 0; ; index++ {
		value <<= 7
		value += uint64(tag[index] & 0x7f)
		if tag[index]>>7 == 0 {
			break
		}
	}
	return
}
