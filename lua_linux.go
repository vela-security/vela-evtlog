package evtlog

import (
	"github.com/vela-security/vela-public/assert"
)

var xEnv assert.Environment

func WithEnv(env assert.Environment) {
	xEnv = env
	xEnv.Warn("not support evtlog with linux")
}
