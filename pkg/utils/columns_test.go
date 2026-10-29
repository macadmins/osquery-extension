package utils

import "testing"

func TestPublishedUID(t *testing.T) {
	for candidate, want := range map[string]string{
		"501": "501", "0": "0", "-2": "-2", "S-1-5-21-1": "", "not-a-uid": "", "": "",
	} {
		if got := PublishedUID(candidate); got != want {
			t.Errorf("PublishedUID(%q) = %q, want %q", candidate, got, want)
		}
	}
}

func TestPublishedUserID(t *testing.T) {
	for _, tc := range []struct {
		candidate, want string
		dropped         bool
	}{
		{"501", "501", false},
		{"0", "0", false},
		{"-2", "-2", false},
		{"S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1001", false},
		{"S-1-12-1-3623811015-3361044348-30300820-1013", "S-1-12-1-3623811015-3361044348-30300820-1013", false},
		{"not-an-id", "", true},
		{"S-1-5-21-abc", "", true},
		{"", "", false},
	} {
		got, dropped := PublishedUserID(tc.candidate)
		if got != tc.want || dropped != tc.dropped {
			t.Errorf("PublishedUserID(%q) = %q, %v; want %q, %v", tc.candidate, got, dropped, tc.want, tc.dropped)
		}
	}
}

func TestBoolToIntString(t *testing.T) {
	if BoolToIntString(true) != "1" || BoolToIntString(false) != "0" {
		t.Error("an INTEGER yes/no column renders as 1 and 0, not true and false")
	}
}
