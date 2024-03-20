package bertlv

import (
	"bytes"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"io"
)

type TLV struct {
	Tag      Tag
	Value    []byte
	Children []*TLV
}

func NewValue(tag Tag, value []byte) *TLV {
	return &TLV{Tag: tag, Value: value}
}

func NewChildren(tag Tag, children ...*TLV) *TLV {
	return &TLV{Tag: tag, Children: children}
}

func (tlv *TLV) ReadFrom(r io.Reader) (n int64, err error) {
	data, err := io.ReadAll(r)
	n = int64(len(data))
	if err != nil {
		return
	}
	_, err = tlv.UnmarshalBerTLV(data)
	return
}

func (tlv *TLV) WriteTo(w io.Writer) (n int64, err error) {
	data, err := tlv.MarshalBerTLV()
	if err != nil {
		return 0, err
	}
	_n, err := w.Write(data)
	return int64(_n), err
}

func (tlv *TLV) MarshalJSON() (_ []byte, err error) {
	data, err := tlv.MarshalBerTLV()
	if err != nil {
		return
	}
	return json.Marshal(data)
}

func (tlv *TLV) UnmarshalJSON(data []byte) (err error) {
	var parsed []byte
	if err = json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	_, err = tlv.UnmarshalBerTLV(parsed)
	return
}

func (tlv *TLV) UnmarshalBerTLV(data []byte) (index int, err error) {
	var element TLV
	if err = element.Tag.UnmarshalBinary(data); err != nil {
		err = errors.Wrap(err, fmt.Sprintf("invalid tag at start: %02X", data))
		return
	}
	index = len(element.Tag)
	length, n, err := unmarshalLength(data[index:])
	if err != nil {
		err = errors.Wrap(err, fmt.Sprintf("tag %s: invalid length encoding", element.Tag))
		return
	}
	index += n
	{
		indicatedEndIndex := index + length - 1
		endIndex := len(data) - 1
		if indicatedEndIndex > endIndex {
			err = errors.Errorf("tag %02X: indicated length of value is out of bounds - indicated end index: %d actual end index %d", tlv.Tag, indicatedEndIndex, endIndex)
			return
		}
	}
	if length == 0 {
		*tlv = element
		return
	}
	if element.Tag.Constructed() {
		var n2 int
		for i := index; i < index+length; i += n2 {
			var child TLV
			if n2, err = child.UnmarshalBerTLV(data[i:]); err != nil {
				err = errors.Wrap(err, fmt.Sprintf("tag %s: invalid child object", tlv.Tag))
				return
			}
			element.Children = append(element.Children, &child)
		}
	} else {
		element.Value = data[index : index+length]
	}
	*tlv = element
	index += length
	return
}

func (tlv *TLV) MarshalBerTLV() (_ []byte, err error) {
	if len(tlv.Value) > 0xFFFF {
		return nil, errors.New("element: invalid length")
	}
	var tag []byte
	if tag, err = tlv.Tag.MarshalBinary(); err != nil {
		return nil, err
	}
	value := tlv.Value
	if tlv.Tag.Constructed() {
		var buf bytes.Buffer
		for _, child := range tlv.Children {
			if value, err = child.MarshalBerTLV(); err != nil {
				return nil, err
			}
			buf.Write(value)
		}
		value = buf.Bytes()
	}
	var buf bytes.Buffer
	buf.Write(tag)
	buf.Write(marshalLength(len(value)))
	buf.Write(value)
	return buf.Bytes(), nil
}

func (tlv *TLV) At(index int) *TLV {
	if index > len(tlv.Children) {
		return nil
	}
	return tlv.Children[index]
}

func (tlv *TLV) First(tag Tag) *TLV {
	for _, child := range tlv.Children {
		if bytes.Equal(child.Tag, tag) {
			return child
		}
	}
	return nil
}

func (tlv *TLV) Find(tag Tag) (matches []*TLV) {
	for _, child := range tlv.Children {
		if bytes.Equal(child.Tag, tag) {
			matches = append(matches, child)
		}
	}
	return matches
}

func (tlv *TLV) Select(tags ...Tag) *TLV {
	next := tlv
	for i := 0; i < len(tags); i++ {
		if next = next.First(tags[i]); next == nil {
			return nil
		}
	}
	return next
}

func (tlv *TLV) BitString(definitions ...string) (features []string) {
	bits := &asn1.BitString{
		Bytes:     tlv.Value[1:],
		BitLength: (len(tlv.Value)-1)*8 - int(tlv.Value[0]),
	}
	for i := 0; i < bits.BitLength; i++ {
		if bits.At(i) == 1 {
			features = append(features, definitions[i])
		}
	}
	return
}

func (tlv *TLV) Bytes() []byte {
	data, err := tlv.MarshalBerTLV()
	if err != nil {
		panic(err)
	}
	return data
}
