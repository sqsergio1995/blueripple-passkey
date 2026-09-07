package userpresence

import "testing"

func TestHostUIDMapped(t *testing.T) {
	tests := []struct {
		name    string
		uidMap  string
		hostUID uint64
		want    bool
		wantErr bool
	}{
		{
			name:    "initial namespace maps root",
			uidMap:  "0 0 4294967295\n",
			hostUID: 0,
			want:    true,
		},
		{
			name:    "systemd user namespace leaves root unmapped",
			uidMap:  "1000 1000 1\n",
			hostUID: 0,
			want:    false,
		},
		{
			name:    "later range maps root",
			uidMap:  "1000 1000 1\n2000 0 1\n",
			hostUID: 0,
			want:    true,
		},
		{
			name:    "malformed map fails closed",
			uidMap:  "1000 1000\n",
			hostUID: 0,
			wantErr: true,
		},
		{
			name:    "zero-length range fails closed",
			uidMap:  "0 0 0\n",
			hostUID: 0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hostUIDMapped([]byte(tt.uidMap), tt.hostUID)
			if (err != nil) != tt.wantErr {
				t.Fatalf("hostUIDMapped() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("hostUIDMapped() = %v, want %v", got, tt.want)
			}
		})
	}
}
