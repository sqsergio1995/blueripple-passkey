package userpresence

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// UserPresence handles user presence confirmation via fingerprint reader
type UserPresence struct {
	mu            sync.Mutex
	activeRequest *request
	fprintdVerify string
	notifySend    string
}

type request struct {
	timeout          time.Duration
	pendingResult    chan Result
	challengeParam   [32]byte
	applicationParam [32]byte
}

// Result represents the outcome of a user presence check
type Result struct {
	OK    bool
	Error error
}

// New creates a user-presence handler that invokes only trusted system
// executables. The user's PATH is not part of the authentication boundary.
func New() (*UserPresence, error) {
	fprintdVerify, err := trustedExecutable("fprintd-verify")
	if err != nil {
		return nil, err
	}
	notifySend, _ := trustedExecutable("notify-send")
	return &UserPresence{fprintdVerify: fprintdVerify, notifySend: notifySend}, nil
}

// CheckFingerprintVerifier validates the security-sensitive helper without
// starting a fingerprint prompt.
func CheckFingerprintVerifier() error {
	_, err := trustedExecutable("fprintd-verify")
	return err
}

func trustedExecutable(name string) (string, error) {
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/local/bin"} {
		candidate := filepath.Join(dir, name)
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			continue
		}
		info, err := os.Stat(resolved)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Mode().Perm()&0022 != 0 {
			continue
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || !trustedSystemOwner(stat.Uid) {
			continue
		}
		return resolved, nil
	}
	return "", fmt.Errorf("%s must be installed as a root-owned, non-writable executable in /usr/bin, /bin, or /usr/local/bin", name)
}

// trustedSystemOwner accepts the ordinary root UID and the kernel's overflow
// UID only when host root is not representable in the current user namespace.
// systemd uses such a namespace when filesystem-hardening options (for example
// ProtectSystem or PrivateTmp) are enabled on an unprivileged user service.
// In that case a host-root-owned /usr/bin file is reported as overflowuid.
//
// This is used only after the caller has constrained the executable to a fixed
// system directory and rejected group- or world-writable files.
func trustedSystemOwner(uid uint32) bool {
	if uid == 0 {
		return true
	}

	overflowData, err := os.ReadFile("/proc/sys/kernel/overflowuid")
	if err != nil {
		return false
	}
	overflowUID, err := strconv.ParseUint(strings.TrimSpace(string(overflowData)), 10, 32)
	if err != nil || uint64(uid) != overflowUID {
		return false
	}

	uidMap, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return false
	}
	rootMapped, err := hostUIDMapped(uidMap, 0)
	return err == nil && !rootMapped
}

// hostUIDMapped reports whether a host UID appears in a Linux uid_map.
func hostUIDMapped(uidMap []byte, hostUID uint64) (bool, error) {
	lines := strings.Split(strings.TrimSpace(string(uidMap)), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		return false, errors.New("empty uid_map")
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return false, fmt.Errorf("invalid uid_map line %q", line)
		}
		hostStart, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return false, fmt.Errorf("invalid uid_map host start: %w", err)
		}
		length, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil || length == 0 {
			return false, fmt.Errorf("invalid uid_map length %q", fields[2])
		}
		if hostUID >= hostStart && hostUID-hostStart < length {
			return true, nil
		}
	}
	return false, nil
}

// ConfirmPresence requests user presence confirmation via fingerprint
func (up *UserPresence) ConfirmPresence(prompt string, challengeParam, applicationParam [32]byte) (chan Result, error) {
	up.mu.Lock()
	defer up.mu.Unlock()

	timeout := 30 * time.Second

	if up.activeRequest != nil {
		return nil, errors.New("other request already in progress")
	}

	up.activeRequest = &request{
		timeout:          timeout,
		challengeParam:   challengeParam,
		applicationParam: applicationParam,
		pendingResult:    make(chan Result),
	}

	go up.promptFingerprint(up.activeRequest, prompt)

	return up.activeRequest.pendingResult, nil
}

func (up *UserPresence) promptFingerprint(req *request, prompt string) {
	sendResult := func(r Result) {
		select {
		case req.pendingResult <- r:
		case <-time.After(2 * time.Second):
			// Client likely gone
		}

		up.mu.Lock()
		up.activeRequest = nil
		up.mu.Unlock()
	}

	ctx, cancel := context.WithTimeout(context.Background(), req.timeout)
	defer cancel()

	log.Printf("userpresence: prompt=%s", prompt)

	// Send an optional notification without trusting the user's PATH.
	if up.notifySend != "" {
		notifyCmd := exec.CommandContext(ctx, up.notifySend, "-u", "critical", "-t", "30000",
			"BlueRipple Passkey", prompt+"\n\nTouch the fingerprint sensor to approve.")
		go func() {
			if err := notifyCmd.Run(); err != nil && ctx.Err() == nil {
				log.Printf("userpresence: desktop notification failed")
			}
		}()
	}

	// Run fprintd-verify with context timeout
	log.Printf("userpresence: launching fprintd-verify")
	fprintCmd := exec.CommandContext(ctx, up.fprintdVerify)
	fprintCmd.Stdout = io.Discard
	fprintCmd.Stderr = io.Discard

	err := fprintCmd.Run()
	if err != nil {
		log.Printf("userpresence: fingerprint verification failed")
		if ctx.Err() == context.DeadlineExceeded {
			sendResult(Result{OK: false, Error: errors.New("fingerprint verification timed out")})
		} else {
			sendResult(Result{OK: false, Error: err})
		}
		return
	}

	log.Printf("userpresence: fingerprint verified successfully")
	sendResult(Result{OK: true, Error: nil})
}
