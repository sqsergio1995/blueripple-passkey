package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/sqsergio1995/blueripple-passkey/ctap2"
	"github.com/sqsergio1995/blueripple-passkey/fidohid"
	"github.com/sqsergio1995/blueripple-passkey/memory"
	"github.com/sqsergio1995/blueripple-passkey/tpm"
	"github.com/sqsergio1995/blueripple-passkey/tray"
	"github.com/sqsergio1995/blueripple-passkey/usbmon"
	"github.com/sqsergio1995/blueripple-passkey/userpresence"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

type stringListFlag []string

func (values *stringListFlag) String() string { return strings.Join(*values, ",") }
func (values *stringListFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

var (
	backend      = flag.String("backend", "tpm", "Backend to use: tpm or memory")
	device       = flag.String("device", "/dev/tpmrm0", "TPM device path")
	showTray     = flag.Bool("tray", true, "Show the BlueRipple Passkey tray icon")
	autoSwitch   = flag.Bool("auto-switch", true, "Automatically disable virtual key when a YubiKey is plugged in (tray mode only)")
	checkOnly    = flag.Bool("check", false, "Check configuration and Linux prerequisites, then exit")
	showVersion  = flag.Bool("version", false, "Print version information, then exit")
	allowedRPIDs stringListFlag
)

func main() {
	flag.Var(&allowedRPIDs, "allowed-rp-id", "Exact authentik hostname to allow (repeatable)")
	flag.Parse()

	if *showVersion {
		fmt.Printf("blueripple-passkey %s (%s)\n", version, buildTime)
		return
	}

	rpIDEnvironment := os.Getenv("BLUERIPPLE_PASSKEY_RP_IDS")
	if rpIDEnvironment == "" {
		// Keep existing installations working while they transition to the new name.
		rpIDEnvironment = os.Getenv("AUTHENTIK_BIOMETRIC_RP_IDS")
	}
	rpIDs, err := configuredRPIDs(allowedRPIDs, rpIDEnvironment)
	if err != nil {
		log.Fatalf("Invalid authentik relying-party configuration: %v", err)
	}
	if len(rpIDs) == 0 {
		log.Fatal("No authentik host configured. Set BLUERIPPLE_PASSKEY_RP_IDS or pass --allowed-rp-id")
	}

	if *checkOnly {
		if !runChecks(*device, rpIDs) {
			os.Exit(1)
		}
		return
	}

	// Set up logging to stderr (Native Messaging uses stdout for communication)
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	log.Printf("blueripple-passkey starting with backend=%s allowed_rp_ids=%s", *backend, strings.Join(rpIDs, ","))

	// Initialize the signer backend
	var signer ctap2.Signer

	switch *backend {
	case "tpm":
		signer, err = tpm.New(*device)
		if err != nil {
			log.Fatalf("Failed to initialize TPM backend: %v", err)
		}
		log.Printf("TPM backend initialized using %s", *device)
	case "memory":
		signer, err = memory.New()
		if err != nil {
			log.Fatalf("Failed to initialize memory backend: %v", err)
		}
		log.Printf("Memory backend initialized (for testing only)")
	default:
		log.Fatalf("Unknown backend: %s (use 'tpm' or 'memory')", *backend)
	}

	// Initialize user presence handler
	presence, err := userpresence.New()
	if err != nil {
		log.Fatalf("Failed to initialize fingerprint verification: %v", err)
	}
	log.Printf("User presence handler initialized")

	// Initialize credential storage for resident keys
	homeDir, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Failed to get home directory: %v", err)
	}
	storagePath := credentialStoragePath(homeDir)
	storage, err := ctap2.NewCredentialStorage(storagePath)
	if err != nil {
		log.Fatalf("Failed to create credential storage: %v", err)
	}
	log.Printf("Credential storage initialized (%d credentials)", storage.Count())

	// Create CTAP2 handler
	ctap2Handler := ctap2.NewHandler(signer, presence, storage, rpIDs)
	log.Printf("CTAP2 handler initialized")

	runDaemonMode(ctap2Handler)
}

// runDaemonMode creates a virtual FIDO2 HID device and handles CTAPHID traffic.
// If --tray is set, it also shows a system tray icon for toggling the device.
func runDaemonMode(ctap2Handler *ctap2.Handler) {
	ctap2Handler.IsPlatform = false

	if *showTray {
		runDaemonWithTray(ctap2Handler)
	} else {
		runDaemonHeadless(ctap2Handler)
	}
}

// runDaemonHeadless runs the virtual FIDO2 device without a tray icon.
func runDaemonHeadless(ctap2Handler *ctap2.Handler) {
	dev, err := fidohid.New("blueripple-passkey", ctap2Handler)
	if err != nil {
		log.Fatalf("Failed to create virtual FIDO2 device: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down", sig)
		cancel()
	}()

	log.Printf("Virtual FIDO2 HID device daemon started")

	if err := dev.Run(ctx); err != nil && err != context.Canceled {
		log.Fatalf("Device error: %v", err)
	}

	dev.Close()
	log.Printf("Daemon stopped")
}

// runDaemonWithTray runs the virtual FIDO2 device with a system tray icon.
// The tray event loop runs on the main goroutine; the uhid device runs in
// a background goroutine and can be toggled on/off from the tray menu.
func runDaemonWithTray(ctap2Handler *ctap2.Handler) {
	var (
		mu             sync.Mutex
		dev            *fidohid.Device
		devCancel      context.CancelFunc
		autoSwitchOn   = *autoSwitch
		stoppedByAuto  bool // true if auto-switch disabled the device
		yubiKeyPresent bool
	)

	// startDevice creates and runs the virtual HID device in a goroutine.
	startDevice := func() {
		mu.Lock()
		defer mu.Unlock()

		if dev != nil {
			return // already running
		}

		d, err := fidohid.New("blueripple-passkey", ctap2Handler)
		if err != nil {
			log.Printf("Failed to create virtual FIDO2 device: %v", err)
			return
		}

		ctx, c := context.WithCancel(context.Background())
		dev = d
		devCancel = c

		go func() {
			log.Printf("Virtual FIDO2 HID device started")
			if err := d.Run(ctx); err != nil && err != context.Canceled {
				log.Printf("Device error: %v", err)
			}
			d.Close()
			log.Printf("Virtual FIDO2 HID device stopped")
		}()
	}

	// stopDevice destroys the virtual HID device.
	stopDevice := func() {
		mu.Lock()
		defer mu.Unlock()

		if devCancel != nil {
			devCancel()
			devCancel = nil
		}
		if dev != nil {
			dev.Close()
			dev = nil
		}
	}

	// Handle SIGTERM/SIGINT for clean shutdown
	monCtx, monCancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		log.Printf("Received signal %v, shutting down", sig)
		monCancel()
		stopDevice()
		os.Exit(0)
	}()

	// Start the device immediately
	startDevice()

	// Create the tray with auto-switch callback.
	// Declare t first so closures can reference it.
	var t *tray.Tray
	t = tray.New(
		func() { // onEnable
			mu.Lock()
			stoppedByAuto = false
			mu.Unlock()
			startDevice()
		},
		func() { // onDisable
			mu.Lock()
			stoppedByAuto = false
			mu.Unlock()
			stopDevice()
		},
		func() { // onQuit
			monCancel()
			stopDevice()
		},
		func(enabled bool) { // onAutoSwitchChanged
			mu.Lock()
			autoSwitchOn = enabled
			wasStoppedByAuto := stoppedByAuto
			present := yubiKeyPresent
			mu.Unlock()

			if !enabled && wasStoppedByAuto {
				log.Printf("auto-switch disabled, re-enabling virtual device")
				mu.Lock()
				stoppedByAuto = false
				mu.Unlock()
				startDevice()
				t.SetActive(true)
			} else if enabled && present {
				log.Printf("auto-switch enabled with YubiKey present, disabling virtual device")
				mu.Lock()
				stoppedByAuto = true
				mu.Unlock()
				stopDevice()
				t.SetActive(false)
			}
		},
	)
	t.SetAutoSwitch(autoSwitchOn)

	// Start the USB monitor for YubiKey detection
	mon := &usbmon.Monitor{
		VendorID: "1050", // Yubico
		Interval: 2 * time.Second,
		OnInsert: func(product string) {
			mu.Lock()
			yubiKeyPresent = true
			enabled := autoSwitchOn
			if enabled {
				stoppedByAuto = true
			}
			mu.Unlock()

			t.SetYubiKeyDetected(true, product)
			if enabled {
				log.Printf("YubiKey inserted, auto-disabling virtual device")
				stopDevice()
				t.SetActive(false)
			}
		},
		OnRemove: func() {
			mu.Lock()
			yubiKeyPresent = false
			enabled := autoSwitchOn
			wasStoppedByAuto := stoppedByAuto
			if enabled && wasStoppedByAuto {
				stoppedByAuto = false
			}
			mu.Unlock()

			t.SetYubiKeyDetected(false, "")
			if enabled && wasStoppedByAuto {
				log.Printf("YubiKey removed, auto-enabling virtual device")
				startDevice()
				t.SetActive(true)
			}
		},
	}

	go mon.Run(monCtx)

	log.Printf("Starting system tray icon (auto-switch=%v)", autoSwitchOn)
	t.Run()
	log.Printf("Daemon stopped")
}

func configuredRPIDs(flags []string, environment string) ([]string, error) {
	values := append([]string(nil), flags...)
	values = append(values, strings.Split(environment, ",")...)
	seen := make(map[string]struct{})
	for _, raw := range values {
		rpID := strings.ToLower(strings.TrimSpace(raw))
		if rpID == "" {
			continue
		}
		if !validRPID(rpID) {
			return nil, fmt.Errorf("%q must be a hostname without a scheme, path, port, or wildcard", raw)
		}
		seen[rpID] = struct{}{}
	}

	result := make([]string, 0, len(seen))
	for rpID := range seen {
		result = append(result, rpID)
	}
	sort.Strings(result)
	return result, nil
}

func validRPID(rpID string) bool {
	if rpID == "" || len(rpID) > 253 || strings.ContainsAny(rpID, "/:*? \t\r\n") {
		return false
	}
	if net.ParseIP(rpID) != nil {
		return true
	}
	for _, label := range strings.Split(rpID, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func credentialStoragePath(homeDir string) string {
	currentPath := filepath.Join(homeDir, ".local", "share", "blueripple-passkey", "credentials.json")
	legacyPath := filepath.Join(homeDir, ".local", "share", "authentik-biometric", "credentials.json")
	if _, err := os.Stat(currentPath); err == nil {
		return currentPath
	}
	if _, err := os.Stat(legacyPath); err != nil {
		return currentPath
	}
	if err := os.MkdirAll(filepath.Dir(currentPath), 0700); err != nil {
		log.Printf("Could not prepare renamed credential directory: %v", err)
		return legacyPath
	}
	if err := os.Rename(legacyPath, currentPath); err != nil {
		log.Printf("Could not migrate existing credentials: %v", err)
		return legacyPath
	}
	log.Printf("Migrated existing credentials to the current data directory")
	return currentPath
}

func runChecks(tpmDevice string, rpIDs []string) bool {
	type check struct {
		name string
		err  error
	}
	checks := []check{
		{name: "TPM device " + tpmDevice, err: pathExists(tpmDevice)},
		{name: "UHID device /dev/uhid", err: pathExists("/dev/uhid")},
		{name: "trusted fingerprint verifier", err: userpresence.CheckFingerprintVerifier()},
		{name: "desktop notifications", err: commandExists("notify-send")},
	}

	ok := true
	fmt.Printf("BlueRipple Passkey preflight\n")
	fmt.Printf("  allowed authentik host(s): %s\n", strings.Join(rpIDs, ", "))
	for _, item := range checks {
		if item.err != nil {
			fmt.Printf("  [missing] %s: %v\n", item.name, item.err)
			ok = false
			continue
		}
		fmt.Printf("  [ok] %s\n", item.name)
	}
	return ok
}

func pathExists(path string) error {
	_, err := os.Stat(path)
	return err
}

func commandExists(name string) error {
	_, err := exec.LookPath(name)
	return err
}
