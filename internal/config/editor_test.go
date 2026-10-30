package config

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kltngfw/ngfw/internal/domain"
)

func editorManager(t *testing.T, dir string) *Manager {
	t.Helper()
	m, err := NewEditorManager(dir, Defaults())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestEditorDraftSurvivesRestartWithoutPublishingRunning(t *testing.T) {
	dir := t.TempDir()
	m := editorManager(t, dir)
	c := m.Candidate()
	c.MaxSessions += 17
	if errs := m.SetCandidateIfValid(c); len(errs) != 0 {
		t.Fatal(errs)
	}
	m.MarkCandidateValidation(true)
	restarted := editorManager(t, dir)
	if configDigest(restarted.Candidate()) != configDigest(c) || configDigest(restarted.Running()) != configDigest(Defaults()) {
		t.Fatal("draft lost or promoted to Running")
	}
	if state, _, _, _ := restarted.CandidateValidation(); state != "NOT_RUN" {
		t.Fatalf("validation must be repeated after restart: %s", state)
	}
	if _, err := os.Stat(filepath.Join(dir, "running.json")); !os.IsNotExist(err) {
		t.Fatalf("API editor published running.json: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, "candidate.json"))
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0640 {
		t.Fatalf("candidate mode: %v", info.Mode())
	}
}

func TestEditorFollowsEngineButPreservesPendingDraft(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "untouched", true: "pending"}[pending], func(t *testing.T) {
			dir := t.TempDir()
			m := editorManager(t, dir)
			base := m.Running()
			if err := m.SyncRunning(base, domain.ConfigVersion{Version: 4}); err != nil {
				t.Fatal(err)
			}
			draft := m.Candidate()
			if pending {
				draft.MaxSessions += 17
				if errs := m.SetCandidate(draft); len(errs) != 0 {
					t.Fatal(errs)
				}
			}
			m = editorManager(t, dir)
			next := base
			next.MaxSessions += 31
			if err := m.SyncRunning(next, domain.ConfigVersion{Version: 5}); err != nil {
				t.Fatal(err)
			}
			m = editorManager(t, dir)
			wanted := next
			if pending {
				wanted = draft
			}
			if configDigest(m.Candidate()) != configDigest(wanted) || m.Version().Version != 5 {
				t.Fatal("engine synchronization lost a draft or retained an untouched stale editor")
			}
		})
	}
}

func TestEditorCommitAndRollbackDoNotResurrectDraft(t *testing.T) {
	dir := t.TempDir()
	m := editorManager(t, dir)
	original := m.Running()
	draft := m.Candidate()
	draft.MaxSessions += 17
	if errs := m.SetCandidate(draft); len(errs) != 0 {
		t.Fatal(errs)
	}
	if err := m.SyncRunning(draft, domain.ConfigVersion{Version: 1}); err != nil {
		t.Fatal(err)
	}
	m = editorManager(t, dir)
	if err := m.SyncRollback(original, domain.ConfigVersion{Version: 2}); err != nil {
		t.Fatal(err)
	}
	m = editorManager(t, dir)
	if configDigest(m.Candidate()) != configDigest(original) || configDigest(m.Running()) != configDigest(original) || m.Version().Version != 2 {
		t.Fatal("rollback resurrected a previously committed draft")
	}
}

func TestEditorSaveFailureDoesNotReplaceCandidate(t *testing.T) {
	for _, validOnly := range []bool{false, true} {
		t.Run(map[bool]string{false: "object editor", true: "JSON editor"}[validOnly], func(t *testing.T) {
			dir := t.TempDir()
			m := editorManager(t, dir)
			old := m.Candidate()
			c := m.Candidate()
			c.MaxSessions += 17
			// Force rename failure on every OS, including root-run Linux tests.
			if err := os.Mkdir(filepath.Join(dir, "candidate.json"), 0700); err != nil {
				t.Fatal(err)
			}
			var errs []string
			if validOnly {
				errs = m.SetCandidateIfValid(c)
			} else {
				errs = m.SetCandidate(c)
			}
			if len(errs) == 0 || configDigest(m.Candidate()) != configDigest(old) {
				t.Fatal("save failure was hidden or modified the in-memory candidate")
			}
			files, _ := filepath.Glob(filepath.Join(dir, ".candidate-*.tmp"))
			if len(files) != 0 {
				t.Fatalf("temporary files leaked: %v", files)
			}
		})
	}
}

func TestEditorCorruptStateIsNotSilentlyDiscarded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "candidate.json"), []byte(`{"schema_version":1,"candidate":`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewEditorManager(dir, Defaults()); err == nil {
		t.Fatal("corrupt draft was silently replaced by defaults")
	}
}
