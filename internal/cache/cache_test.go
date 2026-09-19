package cache

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCacheOfflineKeepsExpired(t *testing.T) {
	c := &FileCache{Dir: t.TempDir()}
	if e := c.Put("x", map[string]int{"n": 1}, time.Nanosecond); e != nil {
		t.Fatal(e)
	}
	time.Sleep(time.Millisecond)
	var v map[string]int
	if ok, _ := c.Get("x", &v, false); ok {
		t.Fatal("expected expired")
	}
	if ok, e := c.Get("x", &v, true); e != nil || !ok || v["n"] != 1 {
		t.Fatalf("%v %v %#v", ok, e, v)
	}
	_ = filepath.Separator
}
