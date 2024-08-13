package queryparser

import "sync"

type KVPairs struct {
	mt sync.Mutex
	v  []KVPair
}

func NewKVPairs() *KVPairs {
	return &KVPairs{}
}

func (kvs *KVPairs) Add(column string, value []byte) *KVPairs {
	if column == "" || len(value) == 0 {
		return kvs
	}

	kvs.mt.Lock()
	defer kvs.mt.Unlock()

	kvs.v = append(kvs.v, NewKeyValue(column, value))
	return kvs
}

func (kvs *KVPairs) Merge(kvp *KVPairs) *KVPairs {
	if kvp == nil {
		return kvs
	}

	kvs.mt.Lock()
	defer kvs.mt.Unlock()

	kvs.v = append(kvs.v, kvp.v...)
	return kvs
}

func (kvs *KVPairs) GetAll() []KVPair {
	if kvs == nil {
		return nil
	}

	kvs.mt.Lock()         //nolint:staticcheck
	defer kvs.mt.Unlock() //nolint:staticcheck

	return kvs.v
}

type KVPair struct {
	Column string
	Value  []byte
}

func NewKeyValue(column string, value []byte) KVPair {
	return KVPair{
		Column: column,
		Value:  value,
	}
}
