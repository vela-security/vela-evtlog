//go:build windows
// +build windows

package evtlog

import (
	cond "github.com/vela-security/vela-cond"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
	"go.uber.org/ratelimit"
)

type config struct {
	name    string
	begin   bool
	channel []channel
	bkt     []string
	pass    []uint64
	ignore  *cond.Ignore
	filter  *cond.Combine
	chains  lua.UserKV
	sdk     lua.Writer
	pipe    *pipe.Px
	limit   ratelimit.Limiter
	co      *lua.LState
}

type channel struct {
	name  string
	query string
}

func def(L *lua.LState) *config {
	return &config{
		co:     xEnv.Clone(L),
		begin:  false,
		pipe:   pipe.New(pipe.Env(xEnv)),
		ignore: cond.NewIgnore(),
		filter: cond.NewCombine(),
		chains: lua.NewUserKV(),
		bkt:    []string{winEvBucketOffset},
	}
}

func newConfig(L *lua.LState) *config {
	tab := L.CheckTable(1)
	cfg := def(L)
	tab.Range(func(key string, val lua.LValue) {
		cfg.NewIndex(L, key, val)
	})

	if e := cfg.valid(); e != nil {
		L.RaiseError("%v", e)
		return nil
	}

	cfg.co = L

	return cfg
}

func (cfg *config) NewIndex(L *lua.LState, key string, val lua.LValue) {
	switch key {

	case "name":
		cfg.name = val.String()

	case "begin":
		cfg.begin = lua.CheckBool(L, val)

	case "to":
		cfg.sdk = auxlib.CheckWriter(val, L)

	case "bucket":
		switch val.Type() {

		case lua.LTString:
			cfg.bkt = []string{val.String()}

		case lua.LTTable:
			cfg.bkt = auxlib.LTab2SS(val.(*lua.LTable))

		default:
			L.RaiseError("invalid bucket type , must be string or table ,got %s", val.Type().String())

		}

	case "pass":
		switch val.Type() {
		case lua.LTNumber:
			cfg.pass = append(cfg.pass, uint64(val.(lua.LNumber)))

		case lua.LTTable:
			arr := val.(*lua.LTable)
			cfg.pass = append(cfg.pass, auxlib.LTab2SUI64(arr)...)
		}

	default:
		L.RaiseError("%s config not found %s field", winEvTypeOf, key)
	}

}

func (cfg *config) valid() error {
	return nil
}
