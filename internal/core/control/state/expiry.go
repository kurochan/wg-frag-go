package state

import "time"

const expirySetInitialCapacity = 64

// expirySet keeps bounded session/epoch tombstones in deadline order. The
// state owner calls prune before admission, so no background timer is needed.
type expirySet[K comparable] struct {
	entries []expiryEntry[K]
	index   map[K]int
	limit   int
}

type expiryEntry[K comparable] struct {
	key     K
	expires time.Time
}

func newExpirySet[K comparable](limit int) *expirySet[K] {
	initial := limit
	if initial > expirySetInitialCapacity {
		initial = expirySetInitialCapacity
	}
	return &expirySet[K]{
		entries: make([]expiryEntry[K], 0, initial),
		index:   make(map[K]int, initial),
		limit:   limit,
	}
}

func (s *expirySet[K]) full() bool { return len(s.entries) >= s.limit }

func (s *expirySet[K]) contains(key K) bool {
	_, ok := s.index[key]
	return ok
}

func (s *expirySet[K]) retain(key K, expires time.Time) bool {
	if index, ok := s.index[key]; ok {
		if expires.After(s.entries[index].expires) {
			s.entries[index].expires = expires
			s.siftDown(index)
			s.siftUp(s.index[key])
		}
		return true
	}
	if s.full() {
		return false
	}
	s.index[key] = len(s.entries)
	s.entries = append(s.entries, expiryEntry[K]{key: key, expires: expires})
	s.siftUp(len(s.entries) - 1)
	return true
}

func (s *expirySet[K]) prune(now time.Time) {
	for len(s.entries) != 0 && !now.Before(s.entries[0].expires) {
		last := len(s.entries) - 1
		key := s.entries[0].key
		delete(s.index, key)
		if last == 0 {
			s.entries = s.entries[:0]

			continue
		}
		s.entries[0] = s.entries[last]
		s.index[s.entries[0].key] = 0
		s.entries = s.entries[:last]
		s.siftDown(0)
	}
}

func (s *expirySet[K]) siftUp(index int) {
	for index > 0 {
		parent := (index - 1) / 2
		if !s.entries[index].expires.Before(s.entries[parent].expires) {
			return
		}
		s.swap(index, parent)
		index = parent
	}
}

func (s *expirySet[K]) siftDown(index int) {
	for {
		left := index*2 + 1
		if left >= len(s.entries) {
			return
		}
		smallest := left
		right := left + 1
		if right < len(s.entries) && s.entries[right].expires.Before(s.entries[left].expires) {
			smallest = right
		}
		if !s.entries[smallest].expires.Before(s.entries[index].expires) {
			return
		}
		s.swap(index, smallest)
		index = smallest
	}
}

func (s *expirySet[K]) swap(left, right int) {
	s.entries[left], s.entries[right] = s.entries[right], s.entries[left]
	s.index[s.entries[left].key] = left
	s.index[s.entries[right].key] = right
}
