//go:build windows
// +build windows

package evtlog

import (
	"context"
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-evtlog/watch"
	"github.com/vela-security/vela-public/auxlib"
	"github.com/vela-security/vela-public/catch"
	"github.com/vela-security/vela-public/lua"
	"github.com/vela-security/vela-public/pipe"
)

type WinEv struct {
	lua.ProcEx
	cfg     *config
	ctx     context.Context
	stop    context.CancelFunc
	watcher *watch.WinLogWatcher
}

func newWinEv(cfg *config) *WinEv {
	w := &WinEv{cfg: cfg}
	w.V(lua.PTInit, winEvTypeOf)
	return w
}

func (wv *WinEv) bookmark(evt *watch.WinLogEvent) {
	if len(wv.cfg.bkt) == 0 {
		return
	}

	err := xEnv.Bucket(wv.cfg.bkt...).Push(evt.Channel, auxlib.S2B(evt.Bookmark), 0)
	if err != nil {
		audit.NewEvent("win-log").
			Subject("bbolt db save fail").
			From(wv.cfg.co.CodeVM()).
			Msg("windows vela-event log save last fail").
			E(err).Log().Put()
	}
}

func (wv *WinEv) require(id uint64) pipe.Fn {
	val := wv.cfg.chains.Get(auxlib.ToString(id))
	if val == lua.LNil || val == nil {
		return nil
	}
	return wv.cfg.pipe.LFunc(val.(*lua.LFunction))
}

func (wv *WinEv) call(evt *watch.WinLogEvent) {
	pv := wv.require(evt.EventId)
	if pv != nil {
		if e := pv(evt, wv.cfg.co); e != nil {
			audit.Errorf("%s vela-event id %d pipe call fail %v", wv.Name(), evt.EventId, e).
				From(wv.cfg.co.CodeVM()).Put()
			return
		}
	}

	wv.cfg.pipe.Do(evt, wv.cfg.co, func(err error) {
		xEnv.Errorf("%s vela-event %s pipe call fail %v", wv.Name(), evt.EventId, err)
	})
}

func (wv *WinEv) send(evt *watch.WinLogEvent) {
	if wv.cfg.sdk == nil {
		return
	}
	_, err := wv.cfg.sdk.Write(evt.Bytes())
	if err != nil {
		xEnv.Errorf("tunnel write %v", err)
		return
	}
}

func (wv *WinEv) wait() {
	if wv.cfg.limit == nil {
		return
	}

	wv.cfg.limit.Take()
}

func (wv *WinEv) help(evt *watch.WinLogEvent) {
	if wv.cfg.ignore.Match(evt) {
		return
	}

	if !wv.cfg.filter.Match(evt) {
		return
	}

	wv.send(evt)
	wv.call(evt)

}

func (wv *WinEv) accpet() {
	for {
		select {

		case <-wv.ctx.Done():
			return
		case evt := <-wv.watcher.Event():
			wv.wait()
			wv.bookmark(evt)
			wv.help(evt)

		case err := <-wv.watcher.Error():
			audit.NewEvent("beat-windows-log").
				Subject("windows vela-event log fail").
				From(wv.cfg.co.CodeVM()).
				Msg("windows 系统日志获取失败").
				E(err).Log().Put()
		}
	}
}

func (wv *WinEv) Start() error {

	watcher, err := watch.New()
	if err != nil {
		return err
	}

	ctx, stop := context.WithCancel(context.Background())
	wv.ctx = ctx
	wv.stop = stop
	wv.watcher = watcher

	for _, item := range wv.cfg.channel {
		wv.subscribe(item.name, item.query)
	}

	xEnv.Spawn(0, wv.accpet)
	return nil
}

func (wv *WinEv) Reload() error {
	errs := catch.New()
	for _, name := range wv.watcher.Watches() {
		if !wv.inChannel(name) {
			errs.Try(name, wv.watcher.RemoveSubscription(name))
		}
	}
	return errs.Wrap()
}

func (wv *WinEv) Close() error {
	wv.stop()
	wv.watcher.Shutdown()
	return nil
}

func (wv *WinEv) Name() string {
	return wv.cfg.name
}

func (wv *WinEv) Type() string {
	return winEvTypeOf
}
