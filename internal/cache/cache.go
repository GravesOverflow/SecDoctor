package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

const schemaVersion = 1

type entry struct {
	Schema  int             `json:"schema"`
	Created time.Time       `json:"created"`
	TTL     time.Duration   `json:"ttl"`
	Data    json.RawMessage `json:"data"`
}

type FileCache struct{ Dir string }

func Default() (*FileCache, error) {
	d, err := os.UserCacheDir()
	if err != nil {
		return nil, err
	}
	d = filepath.Join(d, "secdoctor", "v1")
	if err := os.MkdirAll(d, 0700); err != nil {
		return nil, err
	}
	return &FileCache{Dir: d}, nil
}

func (c *FileCache) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(c.Dir, hex.EncodeToString(sum[:])+".json")
}

func (c *FileCache) Get(key string, dst any, offline bool) (bool, error) {
	b, err := os.ReadFile(c.path(key))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	var e entry
	if err := json.Unmarshal(b, &e); err != nil {
		return false, err
	}
	if e.Schema != schemaVersion {
		return false, nil
	}
	if !offline && e.TTL > 0 && time.Since(e.Created) > e.TTL {
		return false, nil
	}
	return true, json.Unmarshal(e.Data, dst)
}

func (c *FileCache) Put(key string, value any, ttl time.Duration) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	b, err := json.Marshal(entry{Schema: schemaVersion, Created: time.Now().UTC(), TTL: ttl, Data: data})
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(c.Dir, ".secdoctor-cache-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, c.path(key))
}

func (c *FileCache) Clear() error {
	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			if err := os.Remove(filepath.Join(c.Dir, e.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *FileCache) Stats() (int, int64, error) {
	entries, err := os.ReadDir(c.Dir)
	if err != nil {
		return 0, 0, err
	}
	var n int
	var size int64
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		i, err := e.Info()
		if err == nil {
			n++
			size += i.Size()
		}
	}
	return n, size, nil
}
