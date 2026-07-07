package logs_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/ivan-khludov/obscura/internal/logs"
)

func TestNewReader(t *testing.T) {
	r := logs.NewReader()
	if r == nil || r.UnitName != logs.DefaultUnitName {
		t.Fatalf("unexpected reader: %#v", r)
	}
}

func TestReader_Print_ok(t *testing.T) {
	var buf bytes.Buffer
	var name string
	var args []string
	r := &logs.Reader{
		UnitName: "sing-box.service",
		RunCommand: func(_ context.Context, cmdName string, cmdArgs []string, stdout, _ io.Writer) error {
			name = cmdName
			args = append([]string(nil), cmdArgs...)
			_, err := stdout.Write([]byte("log line\n"))
			return err
		},
	}
	if err := r.Print(context.Background(), &buf, false, ""); err != nil {
		t.Fatal(err)
	}
	if name != "journalctl" {
		t.Fatalf("command = %q", name)
	}
	want := []string{"-u", "sing-box.service", "--no-pager", "-o", "cat"}
	if len(args) != len(want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
	if buf.String() != "log line\n" {
		t.Fatalf("output = %q", buf.String())
	}
}

func TestReader_Print_withSinceAndFollow(t *testing.T) {
	var args []string
	r := &logs.Reader{
		UnitName: "sing-box.service",
		RunCommand: func(_ context.Context, _ string, cmdArgs []string, _, _ io.Writer) error {
			args = append([]string(nil), cmdArgs...)
			return nil
		},
	}
	if err := r.Print(context.Background(), &bytes.Buffer{}, true, "1 hour ago"); err != nil {
		t.Fatal(err)
	}
	if !containsAll(args, "--since", "1 hour ago", "-f") {
		t.Fatalf("args = %#v", args)
	}
}

func TestReader_Print_exitStatusIgnored(t *testing.T) {
	r := &logs.Reader{
		RunCommand: func(context.Context, string, []string, io.Writer, io.Writer) error {
			return errors.New("exit status 1")
		},
	}
	if err := r.Print(context.Background(), &bytes.Buffer{}, false, ""); err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestReader_Print_error(t *testing.T) {
	r := &logs.Reader{
		RunCommand: func(context.Context, string, []string, io.Writer, io.Writer) error {
			return errors.New("journalctl missing")
		},
	}
	err := r.Print(context.Background(), &bytes.Buffer{}, false, "")
	if err == nil || !strings.Contains(err.Error(), "journalctl:") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestReader_Print_defaultRunCommand(t *testing.T) {
	r := logs.NewReader()
	err := r.Print(context.Background(), &bytes.Buffer{}, false, "")
	if err != nil {
		t.Fatal(err)
	}
}

func containsAll(args []string, want ...string) bool {
	for _, item := range want {
		found := false
		for _, arg := range args {
			if arg == item {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
