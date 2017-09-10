package redis

import (
	"fmt"
	"github.com/garyburd/redigo/redis"
	"github.com/huangjunwen/jimu/mw/reftoken"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func init() {
	reftoken.RegistKVStoreCreator("redis", createRedisStore)
	reftoken.RegistKVStoreCreator("rediss", createRedisStore)
}

type redisStore struct {
	pool   *redis.Pool
	prefix string
}

func (rs *redisStore) key(k string) string {
	return strings.Join([]string{rs.prefix, k}, ":")
}

func (rs *redisStore) Set(kvs map[string]string, ttl int) error {

	if len(kvs) == 0 {
		return nil
	}

	conn := rs.pool.Get()
	defer conn.Close()

	if err := conn.Send("MULTI"); err != nil {
		return err
	}
	for k, v := range kvs {
		key := rs.key(k)
		if err := conn.Send("SET", key, v, "EX", ttl); err != nil {
			return err
		}
	}
	_, err := conn.Do("EXEC")
	return err

}

func (rs *redisStore) Get(ks []string) ([]string, error) {

	if len(ks) == 0 {
		return nil, nil
	}

	keys := make([]interface{}, len(ks))
	for i, k := range ks {
		keys[i] = rs.key(k)
	}

	conn := rs.pool.Get()
	defer conn.Close()

	reply, err := conn.Do("MGET", keys...)
	return redis.Strings(reply, err)

}

func (rs *redisStore) Del(ks []string) error {

	if len(ks) == 0 {
		return nil
	}

	keys := make([]interface{}, len(ks))
	for i, k := range ks {
		keys[i] = rs.key(k)
	}

	conn := rs.pool.Get()
	defer conn.Close()

	_, err := conn.Do("DEL", keys...)
	return err

}

func createRedisStore(u *url.URL) (reftoken.KVStore, error) {

	pool := &redis.Pool{
		MaxIdle: 10,
	}
	ret := &redisStore{
		pool:   pool,
		prefix: "reftok",
	}

	q := u.Query()

	if v, ok := q["prefix"]; ok && len(v) != 0 {
		ret.prefix = v[0]
	}

	if v, ok := q["max_idle"]; ok && len(v) != 0 {
		max_idle, err := strconv.Atoi(v[0])
		if err != nil {
			return nil, fmt.Errorf("max_idle: %s", err)
		}
		pool.MaxIdle = max_idle
	}

	if v, ok := q["idle_timeout"]; ok && len(v) != 0 {
		idle_timeout, err := time.ParseDuration(v[0])
		if err != nil {
			return nil, fmt.Errorf("idle_timeout: %s", err)
		}
		pool.IdleTimeout = idle_timeout
	}

	ustring := u.String()
	pool.Dial = func() (redis.Conn, error) {
		return redis.DialURL(ustring)
	}

	return ret, nil

}
