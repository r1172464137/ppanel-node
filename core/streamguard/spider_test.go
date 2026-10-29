package streamguard

import (
	"fmt"
	"strings"
	"testing"
)

func TestSpiderParametersBoundedForPinnedXrayFallback(t *testing.T) {
	for _, value := range []string{"", "/", "/path?p=100-200&c=1-2&t=1-4&i=10-100&r=100-500&other=value", "/?p=4096&c=8&t=8&i=30000&r=5000", "/?p=0-0&c=0&t=0&i=0&r=0"} {
		if err := ValidateURI("spider_x", value, true); err != nil {
			t.Errorf("valid %q: %v", value, err)
		}
	}
	for _, value := range []string{
		"/%", "/?p=%", "/?p=-1", "/?c=-1", "/?t=1-2-3", "/?i=5-1", "/?r=+1", "/?p=", "/?p=4097", "/?c=9", "/?t=17", "/?i=30001", "/?r=5001", "/?p=18446744073709551616", "/?p=999999999999999999999999999999999999", "/?p=1&p=2", "/?%70=1&p=2", "/?P=1", "/?x=1&x=2", "/?c=8&t=9", "/" + strings.Repeat("x", MaxSpiderURIBytes),
	} {
		if err := ValidateURI("spider_x", value, true); err == nil {
			t.Errorf("unsafe spider URI accepted: %q", value)
		}
	}
	parts := make([]string, 0, MaxSpiderQueryKeys+1)
	for i := 0; i <= MaxSpiderQueryKeys; i++ {
		parts = append(parts, fmt.Sprintf("x%d=1", i))
	}
	if err := ValidateURI("spider_x", "/?"+strings.Join(parts, "&"), true); err == nil {
		t.Fatal("excess query keys accepted")
	}
}
