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
		if !ok || stat.Uid != 0 {
			continue
		}
		return resolved, nil
	}
	return "", fmt.Errorf("%s must be installed as a root-owned, non-writable executable in /usr/bin, /bin, or /usr/local/bin", name)
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
