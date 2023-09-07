package tibe

import "sync"

type typedMap[U comparable, T interface{}] struct {
	sync.Map
}

func (m *typedMap[K, V]) Load(key K) (value V, ok bool) {
	v, loaded := m.Map.Load(key)
	if loaded {
		return v.(V), loaded
	}

	return value, loaded
}

func (m *typedMap[U, T]) Store(key U, value T) {
	m.Map.Store(key, value)
}

func (m *typedMap[U, T]) Delete(key U) {
	m.Map.Delete(key)
}

func (m *typedMap[U, T]) Range(f func(key U, value T) bool) {
	m.Map.Range(func(key, value any) bool {
		return f(key.(U), value.(T))
	})
}

func (m *typedMap[U, T]) LoadAndDelete(key U) (value T, loaded bool) {
	v, loaded := m.Map.LoadAndDelete(key)
	if !loaded {
		return value, false
	}

	return v.(T), true
}

func (m *typedMap[K, V]) LoadOrStore(key K, value V) (actual V, loaded bool) {
	v, loaded := m.Map.LoadOrStore(key, value)
	// always returns a value, so we can always cast it.
	return v.(V), loaded
}
