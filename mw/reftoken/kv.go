package reftoken

// KV represents key/value pair.
type KV struct {
	Key   string
	Value string
}

// KVStore stores key/value pairs.
type KVStore interface {
	// Set multiple key/value pairs with ttl. Empty values should be ignored.
	Set(kvs []KV, ttl int) error
	// Get values of keys, NOTE: the return slice must
	// have the same size of ks. If a key is not found,
	// "" should be returned.
	Get(ks []string) ([]string, error)
	// Delete keys.
	Del(ks []string) error
}
