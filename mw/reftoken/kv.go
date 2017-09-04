package reftoken

import (
	"fmt"
	"net/url"
)

// KVStore stores key/value pairs.
type KVStore interface {
	// Set multiple key/value pairs with ttl. Empty values should be ignored.
	Set(kvs map[string]string, ttl int) error
	// Get values of keys, NOTE: the return slice must
	// have the same size of ks. If a key is not found,
	// "" should be returned.
	Get(ks []string) ([]string, error)
	// Delete keys.
	Del(ks []string) error
}

var (
	kvStoreCreators = map[string]func(*url.URL) (KVStore, error){}
)

// RegistKVStoreCreator regist kv store creator for a given name. This function
// is not thread-safe and should be used only in init functions.
func RegistKVStoreCreator(name string, creator func(*url.URL) (KVStore, error)) {
	kvStoreCreators[name] = creator
}

// NewKVStore creates a new kv store from url.
func NewKVStore(u *url.URL) (KVStore, error) {

	creator, ok := kvStoreCreators[u.Scheme]
	if !ok {
		return nil, fmt.Errorf("KVStore scheme name %+q not found. Maybe forget to import the driver?",
			u.Scheme)
	}
	return creator(u)

}
