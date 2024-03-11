package utils

import (
	"fmt"
	"sync"
)

type StringSlice []string

func (s *StringSlice) String() string {
	return fmt.Sprintf("%v", *s)
}

func (s *StringSlice) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func (s *StringSlice) Get(ind int) string {
	if s == nil || len(*s) <= ind {
		return ""
	}

	return (*s)[ind]
}

type LockedKeyValue[T any] struct {
	mt sync.Mutex
	m  map[string]T
}

func NewLockedKeyValue[T any]() *LockedKeyValue[T] {
	return &LockedKeyValue[T]{
		m: make(map[string]T),
	}
}

func (l *LockedKeyValue[T]) Add(key string, value T) {
	if key == "" {
		return
	}

	l.mt.Lock()
	defer l.mt.Unlock()
	l.m[key] = value
}

func (l *LockedKeyValue[T]) Get(key string) (T, bool) {
	l.mt.Lock()
	defer l.mt.Unlock()
	val, ok := l.m[key]
	return val, ok
}

func (l *LockedKeyValue[T]) Remove(key string) {
	l.mt.Lock()
	defer l.mt.Unlock()
	delete(l.m, key)
}

func (l *LockedKeyValue[T]) ForEach(fn func(key string, val T)) {
	l.mt.Lock()
	defer l.mt.Unlock()

	for key, val := range l.m {
		fn(key, val)
	}
}

type LockedCounter struct {
	*LockedKeyValue[int]
}

func NewLockedCounter() *LockedCounter {
	return &LockedCounter{
		LockedKeyValue: NewLockedKeyValue[int](),
	}
}

func (l *LockedCounter) Increment(key string) {
	if key == "" {
		return
	}

	val, _ := l.LockedKeyValue.Get(key)
	l.LockedKeyValue.Add(key, val+1)
}

func (l *LockedCounter) Get(key string) (int, bool) {

	return l.LockedKeyValue.Get(key)
}

type LockSet struct {
	*LockedKeyValue[bool]
}

func NewLockSet() *LockSet {
	return &LockSet{
		LockedKeyValue: NewLockedKeyValue[bool](),
	}
}

func (l *LockSet) Add(key string) {
	if key == "" {
		return
	}

	l.LockedKeyValue.Add(key, true)
}

func (l *LockSet) IsAvailable(key string) bool {
	val, ok := l.LockedKeyValue.Get(key)
	return val && ok
}

func (l *LockSet) Remove(key string) {
	l.LockedKeyValue.Remove(key)
}

func (l *LockSet) GetAll() map[string]bool {
	all := make(map[string]bool)
	l.LockedKeyValue.ForEach(func(key string, _ bool) {
		all[key] = true
	})
	return all
}
