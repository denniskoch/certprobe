package resolver

import "testing"

func TestParseServersFromFlag(t *testing.T) {
	tests := []struct {
		in         string
		wantSystem bool
		wantN      int
		wantErr    bool
	}{
		{"system", true, 0, false},
		{"8.8.8.8", false, 1, false},
		{"8.8.8.8:53", false, 1, false},
		{"8.8.8.8,1.1.1.1:53", false, 2, false},
		{"", false, 0, true},
		{"not-an-ip", false, 0, true},
		{"8.8.8.8:abc", false, 0, true},
		{"8.8.8.8,", false, 0, true},
	}

	for _, tt := range tests {
		sys, servers, err := ParseResolversFromFlag(tt.in)
		if tt.wantErr && err == nil {
			t.Fatalf("input %q: expected error, got nil", tt.in)
		}
		if !tt.wantErr && err != nil {
			t.Fatalf("input %q: unexpected error: %v", tt.in, err)
		}
		if sys != tt.wantSystem {
			t.Fatalf("input %q: want system=%v, got %v", tt.in, tt.wantSystem, sys)
		}
		if !tt.wantErr && len(servers) != tt.wantN {
			t.Fatalf("input %q: want %d servers, got %d (%v)", tt.in, tt.wantN, len(servers), servers)
		}
	}
}
