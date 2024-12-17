package cache

import (
	"time"

	"github.com/allegro/bigcache"
	"github.com/eko/gocache/lib/v4/cache"
	bigcacheStore "github.com/eko/gocache/store/bigcache/v4"
)

func New[T comparable]() (*cache.Cache[T], error) {
	cacheClient, err := bigcache.NewBigCache(bigcache.DefaultConfig(time.Hour))
	if err != nil {
		return nil, err
	}
	store := bigcacheStore.NewBigcache(cacheClient)
	return cache.New[T](store), nil
}
