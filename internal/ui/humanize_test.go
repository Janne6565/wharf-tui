package ui

import (
	"testing"
	"time"
)

func TestHumanizeAgo(t *testing.T) {
	now := time.Now()
	cases := []struct {
		ts   time.Time
		want string
	}{
		{time.Time{}, ""}, // zero → omitted
		{now.Add(-5 * time.Second), "just now"},
		{now.Add(-70 * time.Second), "1 min ago"},
		{now.Add(-12 * time.Minute), "12 min ago"},
		{now.Add(-90 * time.Minute), "1 hour ago"},
		{now.Add(-3 * time.Hour), "3 hours ago"},
		{now.Add(-30 * time.Hour), "yesterday"},
		{now.Add(-72 * time.Hour), "3 days ago"},
	}
	for _, c := range cases {
		if got := humanizeAgo(c.ts); got != c.want {
			t.Errorf("humanizeAgo(%v) = %q, want %q", c.ts, got, c.want)
		}
	}
}
