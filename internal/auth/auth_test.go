package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		headerVal string
		wantKey   string
		wantErr   error
		wantMsg   string
	}{
		{
			name:    "missing header",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "wrong scheme",
			headerVal: "Bearer abc123",
			wantMsg:   "malformed authorization header",
		},
		{
			name:      "missing key",
			headerVal: "ApiKey",
			wantMsg:   "malformed authorization header",
		},
		{
			name:      "valid key",
			headerVal: "ApiKey abc123",
			wantKey:   "abc123",
		},
		{
			name:      "valid key with extra parts",
			headerVal: "ApiKey abc123 extra",
			wantKey:   "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.headerVal != "" {
				headers.Set("Authorization", tt.headerVal)
			}

			gotKey, err := GetAPIKey(headers)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
				return
			}
			if tt.wantMsg != "" {
				if err == nil || err.Error() != tt.wantMsg {
					t.Fatalf("expected error message %q, got %v", tt.wantMsg, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}
