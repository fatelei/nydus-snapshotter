package namedmutex

import (
	"sync"
)

// NamedMutex wraps sync.Mutex and provides namespaced mutex.
type NamedMutex struct {
	muMap  map[string]*sync.Mutex
	refMap map[string]int

	mu sync.Mutex
}

// Lock locks the mutex of the given name
func (nl *NamedMutex) Lock(name string) {
	nl.mu.Lock()
	if nl.muMap == nil {
		nl.muMap = make(map[string]*sync.Mutex)
	}
	if nl.refMap == nil {
		nl.refMap = make(map[string]int)
	}
	if _, ok := nl.muMap[name]; !ok {
		nl.muMap[name] = &sync.Mutex{}
	}
	mu := nl.muMap[name]
	nl.refMap[name]++
	nl.mu.Unlock()
	mu.Lock()
}

// Unlock unlocks the mutex of the given name
func (nl *NamedMutex) Unlock(name string) {
	nl.mu.Lock()
	mu := nl.muMap[name]
	nl.refMap[name]--
	if nl.refMap[name] <= 0 {
		delete(nl.muMap, name)
		delete(nl.refMap, name)
	}
	nl.mu.Unlock()
	mu.Unlock()
}
