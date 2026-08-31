//go:build linux || darwin

package manager

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
	"time"

	controlapiv1 "github.com/kurochan/wg-frag-go/proto/controlapi/v1"
	"google.golang.org/protobuf/proto"
)

const (
	requestCacheEntries  = 256
	requestCacheLifetime = 10 * time.Minute
)

type mutationCacheEntry struct {
	hash     [32]byte
	result   proto.Message
	err      error
	done     chan struct{}
	finished bool
	at       time.Time
}

// mutationCache makes all mutation RPCs process-locally idempotent. Pending
// entries are retained so concurrent retries cannot execute the operation
// twice; completed entries are bounded and expire.
type mutationCache struct {
	mu       sync.Mutex
	entries  map[[16]byte]*mutationCacheEntry
	capacity int
	lifetime time.Duration
}

func newMutationCache(capacity int, lifetime time.Duration) *mutationCache {
	return &mutationCache{
		entries:  make(map[[16]byte]*mutationCacheEntry),
		capacity: capacity,
		lifetime: lifetime,
	}
}

func mutationRequestHash(kind string, message proto.Message) ([32]byte, error) {
	encoded, err := (proto.MarshalOptions{Deterministic: true}).Marshal(message)
	if err != nil {
		return [32]byte{}, err
	}
	digest := sha256.New()
	_, _ = digest.Write([]byte(kind))
	_, _ = digest.Write([]byte{':'})
	_, _ = digest.Write(encoded)
	var result [32]byte
	copy(result[:], digest.Sum(nil))
	return result, nil
}

func (cache *mutationCache) execute(
	ctx context.Context,
	id [16]byte,
	hash [32]byte,
	operation func() (proto.Message, error),
) (result proto.Message, err error) {
	now := time.Now()
	cache.mu.Lock()
	cache.pruneLocked(now)
	if existing := cache.entries[id]; existing != nil {
		if existing.hash != hash {
			cache.mu.Unlock()
			return nil, NewError(CodeAlreadyExists, "request_id was already used for a different mutation")
		}
		done := existing.done
		cache.mu.Unlock()
		select {
		case <-done:
			if existing.result == nil {
				return nil, existing.err
			}
			return proto.Clone(existing.result), existing.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if !cache.reserveLocked() {
		cache.mu.Unlock()
		return nil, NewError(CodeResourceExhausted, "mutation request cache is full")
	}
	entry := &mutationCacheEntry{hash: hash, done: make(chan struct{}), at: now}
	cache.entries[id] = entry
	cache.mu.Unlock()

	completed := false
	defer func() {
		// Goexit must not leave a permanently pending cache entry. Panics also
		// complete the entry for waiters, but intentionally continue unwinding
		// so the process fails closed instead of serving partially mutated state.
		if !completed {
			result = nil
			err = NewError(CodeInternal, "mutation terminated before completion")
		}
		cache.mu.Lock()
		if result != nil {
			entry.result = proto.Clone(result)
		}
		entry.err = err
		entry.finished = true
		entry.at = time.Now()
		close(entry.done)
		cache.mu.Unlock()
	}()

	result, err = operation()
	completed = true
	if result == nil {
		return nil, err
	}
	return proto.Clone(result), err
}

func (cache *mutationCache) reserveLocked() bool {
	if cache.capacity <= 0 || len(cache.entries) < cache.capacity {
		return true
	}
	var oldestID [16]byte
	var oldestAt time.Time
	found := false
	for id, entry := range cache.entries {
		if !entry.finished || (found && !entry.at.Before(oldestAt)) {
			continue
		}
		oldestID = id
		oldestAt = entry.at
		found = true
	}
	if !found {
		return false
	}
	delete(cache.entries, oldestID)
	return true
}

func (cache *mutationCache) pruneLocked(now time.Time) {
	if cache.lifetime <= 0 {
		return
	}
	for id, entry := range cache.entries {
		if entry.finished && now.Sub(entry.at) > cache.lifetime {
			delete(cache.entries, id)
		}
	}
}

func mutationID(mutation *controlapiv1.MutationContext) ([16]byte, error) {
	if mutation == nil {
		return [16]byte{}, errors.New("missing mutation context")
	}
	return parseRequestID(mutation.GetRequestId())
}

func parseRequestID(raw []byte) ([16]byte, error) {
	if len(raw) != 16 {
		return [16]byte{}, errors.New("request_id must contain exactly 16 bytes")
	}
	var id [16]byte
	copy(id[:], raw)
	if id == ([16]byte{}) {
		return [16]byte{}, errors.New("request_id must not be all zeroes")
	}
	return id, nil
}
