// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE.

// Package ratelimit counts events per key in a sliding window, in memory.
// Keys are hashes chosen by the caller; nothing outlives the window.
package ratelimit

import (
	"sync"
	"time"
)

// Limiter allows Max events per key per Window.
type Limiter struct {
	Max    int
	Window time.Duration
	Now    func() time.Time

	mu     sync.Mutex
	events map[string][]time.Time
}

// Allow records an event for key if it is within the limit. It returns
// false, and how long to wait, when it is not.
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	now := l.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.events == nil {
		l.events = map[string][]time.Time{}
	}
	cut := now.Add(-l.Window)
	kept := l.events[key][:0]
	for _, t := range l.events[key] {
		if t.After(cut) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.Max {
		l.events[key] = kept
		return false, kept[0].Add(l.Window).Sub(now)
	}
	l.events[key] = append(kept, now)
	if len(l.events) > 100_000 {
		l.sweep(cut)
	}
	return true, 0
}

func (l *Limiter) sweep(cut time.Time) {
	for k, ts := range l.events {
		if len(ts) == 0 || !ts[len(ts)-1].After(cut) {
			delete(l.events, k)
		}
	}
}
