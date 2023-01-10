//go:build windows

package evtlog

import (
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/auxlib"
)

func (wv *WinEv) subscribe(name, query string) {

	var err error
	if wv.cfg.begin {
		wv.watcher.SubscribeFromBeginning(name, query)
		return
	}

	bookmark, err := xEnv.Bucket(winEvBucketOffset).Value(name)
	if err != nil {
		wv.watcher.SubscribeFromBeginning(name, query)
		return
	}

	audit.NewEvent("win-log").
		Subject("%s last bookmark", name).
		From(wv.cfg.co.CodeVM()).
		Msg("%s", bookmark).Log().Put()

	wv.watcher.SubscribeFromBookmark(name, query, auxlib.B2S(bookmark))
}

func (wv *WinEv) inChannel(name string) bool {
	for _, item := range wv.cfg.channel {
		if item.name == name {
			return true
		}
	}
	return false
}
