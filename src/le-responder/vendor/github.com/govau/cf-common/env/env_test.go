package env

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestString(t *testing.T) {
	lookup := func(name string) (string, bool) {
		switch name {
		case "A":
			return "a", true
		default:
			return "", false
		}
	}
	tests := []struct {
		testName, name, def, want string
	}{
		{"exists, no default given", "A", "", "a"},
		{"exists, default given", "A", "a", "a"},
		{"not exists, no default given", "Z", "", ""},
		{"not exists, default given", "Z", "z", "z"},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			v := VarSet{[]Lookup{lookup}}
			got := v.String(tt.name, tt.def)
			if got != tt.want {
				t.Errorf("String(%q, %q) = %q, want %q", tt.name, tt.def, got, tt.want)
			}
		})
	}
}

func TestMustString(t *testing.T) {
	lookup := func(name string) (string, bool) {
		switch name {
		case "A":
			return "a", true
		default:
			return "", false
		}
	}
	tests := []struct {
		testName, name, want string
		err                  error
	}{
		{"exists", "A", "a", nil},
		{"not exists", "Z", "", NewVarNotFoundErr("Z")},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			defer func() {
				err := recover()
				switch err {
				case nil:
					if tt.err != nil {
						t.Fatalf("got no panic error, want %v", tt.err)
					}
				default:
					if tt.err == nil {
						t.Fatalf("got panic error %v, want none", err)
					} else if !reflect.DeepEqual(err, tt.err) {
						t.Fatalf("got panic error %v, want %v", err, tt.err)
					}
				}
			}()
			v := VarSet{[]Lookup{lookup}}
			got := v.MustString(tt.name)
			if got != tt.want {
				t.Errorf("MustString(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestBool(t *testing.T) {
	lookup := func(name string) (string, bool) {
		switch name {
		case "A":
			return "true", true
		case "B":
			return "1", true
		case "C":
			return "false", true
		case "D":
			return "no", true
		default:
			return "", false
		}
	}
	tests := []struct {
		testName, name string
		want, err      bool
	}{
		{"exists, value ok (1)", "A", true, false},
		{"exists, value ok (2)", "B", true, false},
		{"exists, value ok (3)", "C", false, false},
		{"exists, value not ok", "D", false, true},
		{"not exists", "Z", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			v := VarSet{[]Lookup{lookup}}
			got, err := v.Bool(tt.name)
			if tt.err && err == nil {
				t.Fatalf("got no error, want one")
			} else if !tt.err && err != nil {
				t.Fatalf("got error %v, want none", err)
			}
			if got != tt.want {
				t.Errorf("Bool(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestMustBool(t *testing.T) {
	lookup := func(name string) (string, bool) {
		switch name {
		case "A":
			return "true", true
		case "B":
			return "1", true
		case "C":
			return "TRUE", true
		case "D":
			return "false", true
		case "Y":
			return "no", true
		default:
			return "", false
		}
	}
	tests := []struct {
		testName, name string
		want           bool
		err            error
	}{
		{"exists (1)", "A", true, nil},
		{"exists (2)", "B", true, nil},
		{"exists (3)", "C", true, nil},
		{"exists (4)", "D", false, nil},
		{"not exists", "Z", false, nil},
		{"not valid", "Y", false, NewVarNotParsableErr("Y")},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			defer func() {
				err := recover()
				switch err {
				case nil:
					if tt.err != nil {
						t.Fatalf("got no panic error, want %v", tt.err)
					}
				default:
					if tt.err == nil {
						t.Fatalf("got panic error %v, want none", err)
					} else if !reflect.DeepEqual(err, tt.err) {
						t.Fatalf("got panic error %v, want %v", err, tt.err)
					}
				}
			}()
			v := VarSet{[]Lookup{lookup}}
			got := v.MustBool(tt.name)
			if got != tt.want {
				t.Errorf("MustBool(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func TestMustHexEncodedByteArray(t *testing.T) {
	lookup := func(name string) (string, bool) {
		switch name {
		case "A":
			return "61", true // a
		case "APPLE":
			return "6170706c65", true // apple
		case "PARTIAL":
			return "6", true
		default:
			return "", false
		}
	}
	tests := []struct {
		testName string
		name     string
		len      int
		want     []byte
		err      error
	}{
		{"exists (1)", "A", 1, []byte("a"), nil},
		{"exists (2)", "APPLE", 5, []byte("apple"), nil},
		{"not exists", "Z", 1, nil, NewVarNotFoundErr("Z")},
		{"cannot decode", "PARTIAL", 1, nil, NewVarNotParsableErr("PARTIAL")},
		{"wrong length", "APPLE", 42, nil, NewVarNotParsableErr("APPLE")},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			defer func() {
				err := recover()
				switch err {
				case nil:
					if tt.err != nil {
						t.Fatalf("got no panic error, want %v", tt.err)
					}
				default:
					if tt.err == nil {
						t.Fatalf("got panic error %v, want none", err)
					} else if !reflect.DeepEqual(err, tt.err) {
						t.Fatalf("got panic error %v, want %v", err, tt.err)
					}
				}
			}()
			v := VarSet{[]Lookup{lookup}}
			got := v.MustHexEncodedByteArray(tt.name, tt.len)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("MustHexEncodedByteArray(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}

func TestIsVarNotFound(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"true", NewVarNotFoundErr("A"), true},
		{"false", errors.New("other"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVarNotFound(tt.err); got != tt.want {
				t.Errorf("IsVarNotFound(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestIsVarNotParsable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"true", NewVarNotParsableErr("A"), true},
		{"false", errors.New("other"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsVarNotParsable(tt.err); got != tt.want {
				t.Errorf("IsVarNotParsable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}
