package utils

type Set[T comparable] interface {
	Add(T)
	Remove(T)
	Contains(T) bool
	Len() int
	Slice() []T
}

type set[T comparable] struct {
	m map[T]struct{}
}

func NewSet[T comparable]() Set[T] {
	return &set[T]{
		m: make(map[T]struct{}),
	}
}

func NewSetFromSlice[T comparable](slice []T) Set[T] {
	s := NewSet[T]()
	for _, item := range slice {
		s.Add(item)
	}
	return s
}

func (s *set[T]) Add(item T) {
	s.m[item] = struct{}{}
}

func (s *set[T]) Slice() []T {
	slice := make([]T, 0, len(s.m))
	for item := range s.m {
		slice = append(slice, item)
	}
	return slice
}

func (s *set[T]) Remove(item T) {
	delete(s.m, item)
}

func (s *set[T]) Contains(item T) bool {
	if s == nil {
		return false
	}
	_, ok := s.m[item]
	return ok
}

func (s *set[T]) Len() int {
	return len(s.m)
}

type dummyContainsAllSet[T comparable] struct{}

func NewDummyContainsAllSet[T comparable]() Set[T] {
	return &dummyContainsAllSet[T]{}
}

func (s *dummyContainsAllSet[T]) Add(item T) {}

func (s *dummyContainsAllSet[T]) Remove(item T) {}

func (s *dummyContainsAllSet[T]) Contains(item T) bool {
	return true
}

func (s *dummyContainsAllSet[T]) Slice() []T {
	return nil
}

func (s *dummyContainsAllSet[T]) Len() int {
	return 0
}
