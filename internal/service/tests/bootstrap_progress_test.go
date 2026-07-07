package service_test

import (
	"context"
	"testing"

	"github.com/ivan-khludov/obscura/internal/service"
)

func TestBootstrapReportsProgress(t *testing.T) {
	svc, _ := newTestService(t)
	var updates []service.BootstrapProgress
	err := svc.Bootstrap(context.Background(), service.BootstrapOptions{
		Progress: func(p service.BootstrapProgress) {
			updates = append(updates, p)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(updates) == 0 {
		t.Fatal("expected progress updates")
	}
	last := updates[len(updates)-1]
	if last.Percent != 100 {
		t.Fatalf("expected 100%%, got %d (%q)", last.Percent, last.Label)
	}
	if updates[0].Percent <= 0 {
		t.Fatalf("expected first progress > 0, got %d", updates[0].Percent)
	}
}

func TestReportBootstrapProgressNilCallback(t *testing.T) {
	service.ReportBootstrapProgressForTest(service.BootstrapOptions{}, "label", 50)
}

func TestReportBootstrapProgressClamps(t *testing.T) {
	var got service.BootstrapProgress
	service.ReportBootstrapProgressForTest(service.BootstrapOptions{
		Progress: func(p service.BootstrapProgress) { got = p },
	}, "clamped", 150)
	if got.Percent != 100 {
		t.Fatalf("expected 100, got %d", got.Percent)
	}
	service.ReportBootstrapProgressForTest(service.BootstrapOptions{
		Progress: func(p service.BootstrapProgress) { got = p },
	}, "clamped", -5)
	if got.Percent != 0 {
		t.Fatalf("expected 0, got %d", got.Percent)
	}
}

func TestFormatDownloadProgress(t *testing.T) {
	if got := service.FormatDownloadProgressForTest(512, 1024); got != "Downloading sing-box… 50% (512 B / 1.0 KB)" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := service.FormatDownloadProgressForTest(2048, 0); got != "Downloading sing-box… 2.0 KB" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := service.FormatDownloadProgressForTest(0, 0); got != "Downloading sing-box…" {
		t.Fatalf("unexpected: %q", got)
	}
	if got := service.FormatDownloadProgressForTest(2<<20, 1<<20); got != "Downloading sing-box… 100% (2.0 MB / 1.0 MB)" {
		t.Fatalf("unexpected: %q", got)
	}
}

func TestFormatByteSize(t *testing.T) {
	cases := map[int64]string{
		500: "500 B", 1536: "1.5 KB", 3 << 20: "3.0 MB",
	}
	for n, want := range cases {
		if got := service.FormatByteSizeForTest(n); got != want {
			t.Fatalf("%d: got %q want %q", n, got, want)
		}
	}
}
