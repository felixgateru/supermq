// Copyright (c) Abstract Machines
// SPDX-License-Identifier: Apache-2.0

package connections

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/absmach/supermq/pkg/errors"
)

var errInvalidConnType = errors.New("invalid connection type")

type ConnType uint8

const (
	Invalid ConnType = iota
	Publish
	Subscribe
)

func (c *ConnType) UnmarshalJSON(bytes []byte) error {
	var cstr string
	if err := json.Unmarshal(bytes, &cstr); err != nil {
		return err
	}

	nc, err := ParseConnType(cstr)
	if err != nil {
		return err
	}
	*c = nc
	return nil
}

func (c ConnType) MarshalJSON() ([]byte, error) {
	cstr := c.String()
	return json.Marshal(cstr)
}

func CheckConnType(c ConnType) error {
	switch c {
	case Publish:
		return nil
	case Subscribe:
		return nil
	default:
		return fmt.Errorf("Unknown connection type %d", c)
	}
}

func (c ConnType) String() string {
	switch c {
	case Publish:
		return "Publish"
	case Subscribe:
		return "Subscribe"
	default:
		return fmt.Sprintf("Unknown connection type %d", c)
	}
}

func (c ConnType) Permission() (string, error) {
	switch c {
	case Publish:
		return "publish_permission", nil
	case Subscribe:
		return "subscribe_permission", nil
	default:
		return "", fmt.Errorf("Unknown connection type %d", c)
	}
}

func NewType(c uint) (ConnType, error) {
	if err := CheckConnType(ConnType(c)); err != nil {
		return Invalid, err
	}
	return ConnType(c), nil
}

func ParseConnType(c string) (ConnType, error) {
	switch strings.ToLower(c) {
	case "publish":
		return Publish, nil
	case "subscribe":
		return Subscribe, nil
	default:
		return Invalid, errors.Wrap(errInvalidConnType, fmt.Errorf("%s", c))
	}
}
