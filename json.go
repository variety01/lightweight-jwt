package jwt

import (
	"encoding/json"
	"errors"
)

type JSONCodec interface {
	EncodeToJSON(src interface{}) ([]byte, error)
	DecodeFromJSON(content []byte, dst interface{}) error
}

// ErrInvalidJSONContent must be returned by JSONCoded implementations when the content is not valid JSON.
var ErrInvalidJSONContent = errors.New("invalid JSON content")

type defaultJSONCodec struct{}

func (d defaultJSONCodec) DecodeFromJSON(content []byte, dst interface{}) error {
	if err := json.Unmarshal(content, dst); err != nil {
		return ErrInvalidJSONContent
	}

	return nil
}

func (d defaultJSONCodec) EncodeToJSON(src interface{}) ([]byte, error) {
	return json.Marshal(src)
}

var DefaultJSONCodec = defaultJSONCodec{}
