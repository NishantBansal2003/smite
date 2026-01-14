package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/wire"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/buffer"
	"github.com/lightningnetwork/lnd/keychain"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/tor"
	smite "github.com/morehouse/smite/bindings/go"
)

const (
	timeout time.Duration = 30 * time.Second
	retries int           = 3

	// Local network configuration
	bitcoindHost = "127.0.0.1"
	bitcoindPort = "18443" // regtest port
	lndHost      = "127.0.0.1"
	lndPort      = "9735"
	lndRPCPort   = "10009"
)

type DaemonManager struct {
	dataDir     string
	bitcoindCmd *exec.Cmd
	lndCmd      *exec.Cmd
	lndPubKey   string
}

func check(err error) {
	if err != nil {
		log.Fatalf("ERROR: %v", err)
	}
}

func NewDaemonManager() (*DaemonManager, error) {
	// Create temporary directory for data
	dataDir, err := ioutil.TempDir("", "lnd-fuzz-")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %v", err)
	}

	return &DaemonManager{
		dataDir: dataDir,
	}, nil
}

func (dm *DaemonManager) startBitcoind() error {
	log.Println("Starting bitcoind...")

	bitcoindDataDir := filepath.Join(dm.dataDir, "bitcoind")
	if err := os.MkdirAll(bitcoindDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create bitcoind data dir: %v", err)
	}

	dm.bitcoindCmd = exec.Command("bitcoind",
		"-regtest",
		"-datadir="+bitcoindDataDir,
		"-port=18444",
		"-rpcport="+bitcoindPort,
		"-rpcuser=rpcuser",
		"-rpcpassword=rpcpass",
		"-fallbackfee=0.00001",
		"-txindex=1",
		"-server=1",
		"-rest=1",
		"-printtoconsole=0",
		"-zmqpubrawblock=tcp://127.0.0.1:28332",
		"-zmqpubrawtx=tcp://127.0.0.1:28333",
	)

	if err := dm.bitcoindCmd.Start(); err != nil {
		return fmt.Errorf("failed to start bitcoind: %v", err)
	}

	// Wait for bitcoind to be ready
	log.Println("Waiting for bitcoind to be ready...")
	for i := 0; i < 30; i++ {
		cmd := exec.Command("bitcoin-cli",
			"-regtest",
			"-datadir="+bitcoindDataDir,
			"-rpcport="+bitcoindPort,
			"-rpcuser=rpcuser",
			"-rpcpassword=rpcpass",
			"getblockchaininfo",
		)
		output, err := cmd.CombinedOutput()
		ioutil.WriteFile("/bitcoin-cli.log", output, 0644)
		if err == nil {
			log.Println("bitcoind is ready")

			// Create initial blocks
			createBlocksCmd := exec.Command("bitcoin-cli",
				"-regtest",
				"-datadir="+bitcoindDataDir,
				"-rpcport="+bitcoindPort,
				"-rpcuser=rpcuser",
				"-rpcpassword=rpcpass",
				"createwallet", "default",
			)
			createBlocksCmd.Run() // Ignore error if wallet already exists

			// Generate blocks
			generateCmd := exec.Command("bitcoin-cli",
				"-regtest",
				"-datadir="+bitcoindDataDir,
				"-rpcport="+bitcoindPort,
				"-rpcuser=rpcuser",
				"-rpcpassword=rpcpass",
				"-generate", "101",
			)
			if err := generateCmd.Run(); err != nil {
				log.Printf("Warning: failed to generate blocks: %v", err)
			}

			return nil
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("bitcoind failed to become ready")
}

func (dm *DaemonManager) startLnd() error {
	log.Println("Starting lnd...")

	lndDataDir := filepath.Join(dm.dataDir, "lnd")
	if err := os.MkdirAll(lndDataDir, 0755); err != nil {
		return fmt.Errorf("failed to create lnd data dir: %v", err)
	}

	dm.lndCmd = exec.Command("lnd",
		"--noseedbackup",
		"--debuglevel=info",
		"--bitcoin.active",
		"--bitcoin.regtest",
		"--bitcoin.node=bitcoind",
		"--bitcoind.rpchost="+bitcoindHost+":"+bitcoindPort,
		"--bitcoind.rpcuser=rpcuser",
		"--bitcoind.rpcpass=rpcpass",
		"--bitcoind.zmqpubrawblock=tcp://127.0.0.1:28332",
		"--bitcoind.zmqpubrawtx=tcp://127.0.0.1:28333",
		"--lnddir="+lndDataDir,
		"--listen="+lndHost+":"+lndPort,
		"--rpclisten="+lndHost+":"+lndRPCPort,
		"--restlisten="+lndHost+":8080",
		"--tlsextradomain="+lndHost,
	)
	dm.lndCmd.Env = os.Environ()

	if err := dm.lndCmd.Start(); err != nil {
		return fmt.Errorf("failed to start lnd: %v", err)
	}

	// Wait for lnd to be ready
	log.Println("Waiting for lnd to be ready...")
	for i := 0; i < 60; i++ {
		// Try to query lnd's getinfo RPC to verify it's fully ready
		cmd := exec.Command("lncli",
			"--lnddir="+lndDataDir,
			"--rpcserver="+lndHost+":"+lndRPCPort,
			"--network=regtest",
			"getinfo",
		)
		if err := cmd.Run(); err == nil {
			log.Println("lnd RPC is ready")
			return nil
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("lnd failed to become ready")
}

func (dm *DaemonManager) getLndAddr() (*lnwire.NetAddress, error) {
	// Query lnd's identity public key via lncli
	lndDir := filepath.Join(dm.dataDir, "lnd")

	cmd := exec.Command("lncli",
		"--lnddir="+lndDir,
		"--rpcserver="+lndHost+":"+lndRPCPort,
		"--network=regtest",
		"getinfo",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to query lnd getinfo: %v, output: %s", err, string(output))
	}

	// Parse the JSON response
	var info struct {
		IdentityPubkey string `json:"identity_pubkey"`
	}
	if err := json.Unmarshal(output, &info); err != nil {
		return nil, fmt.Errorf("failed to parse lnd getinfo response: %v", err)
	}

	log.Printf("LND identity pubkey: %s", info.IdentityPubkey)

	// Decode the hex pubkey
	pkBytes, err := hex.DecodeString(info.IdentityPubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode pubkey: %v", err)
	}

	pk, err := btcec.ParsePubKey(pkBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse pubkey: %v", err)
	}

	// Resolve the TCP address
	netCfg := &tor.ClearNet{}
	addr, err := netCfg.ResolveTCPAddr("tcp", lndHost+":"+lndPort)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve lnd address: %v", err)
	}

	return &lnwire.NetAddress{
		IdentityKey: pk,
		Address:     addr,
		ChainNet:    wire.TestNet,
	}, nil
}

func (dm *DaemonManager) Cleanup() {
	log.Println("Cleaning up daemons...")

	// Attempt graceful shutdown via SIGTERM. After shutdownTimeout,
	// forcefully kill unresponsive processes.
	const shutdownTimeout = 5 * time.Second

	if dm.lndCmd != nil && dm.lndCmd.Process != nil {
		dm.lndCmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- dm.lndCmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				log.Printf("LND exited with error: %v", err)
			} else {
				log.Println("LND exited gracefully")
			}
		case <-time.After(shutdownTimeout):
			log.Println("LND did not exit gracefully, killing")
			dm.lndCmd.Process.Kill()
			<-done
		}
	}

	if dm.bitcoindCmd != nil && dm.bitcoindCmd.Process != nil {
		dm.bitcoindCmd.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- dm.bitcoindCmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				log.Printf("bitcoind exited with error: %v", err)
			} else {
				log.Println("bitcoind exited gracefully")
			}
		case <-time.After(shutdownTimeout):
			log.Println("bitcoind did not exit gracefully, killing")
			dm.bitcoindCmd.Process.Kill()
			<-done
		}
	}

	if dm.dataDir != "" {
		os.RemoveAll(dm.dataDir)
	}
}

func connect(victim *lnwire.NetAddress) (*brontide.Conn,
	*btcec.PrivateKey, error) {

	// Choose a random private key to connect from, and return it for the caller
	// to use in future protocol messages.
	key, err := btcec.NewPrivateKey()
	check(err)
	keyECDH := &keychain.PrivKeyECDH{PrivKey: key}

	// Do the Noise protocol handshake.
	conn, err := brontide.Dial(keyECDH, victim, timeout, net.DialTimeout)

	return conn, key, err
}

func recvMsg[T lnwire.Message](conn *brontide.Conn) (T, error) {
	for i := 0; i < retries; i++ {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return *new(T), fmt.Errorf("read deadline: %v", err)
		}
		pktLen, err := conn.ReadNextHeader()
		if err != nil {
			return *new(T), fmt.Errorf("read header: %v", err)
		}

		var buf buffer.Read
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return *new(T), fmt.Errorf("read deadline: %v", err)
		}
		rawMsg, err := conn.ReadNextBody(buf[:pktLen])
		if err != nil {
			return *new(T), fmt.Errorf("read body: %v", err)
		}

		msgReader := bytes.NewReader(rawMsg)
		msg, err := lnwire.ReadMessage(msgReader, 0)
		if err != nil {
			// CLN may send peer storage messages, which
			// lnwire.ReadMessage doesn't know how to handle and
			// returns an error.  Just ignore such messages.
			continue
		}

		typedMsg, ok := msg.(T)
		if ok {
			return typedMsg, nil
		}

		// Unexpected message type.
		log.Printf("WARN: expected %v, got %v",
			(*new(T)).MsgType().String(), msg.MsgType().String())
	}

	return *new(T), fmt.Errorf("victim didn't send %v message", (*new(T)).MsgType().String())
}

func sendMsg(conn *brontide.Conn, msg lnwire.Message) error {
	var buf bytes.Buffer
	if _, err := lnwire.WriteMessage(&buf, msg, 0); err != nil {
		return fmt.Errorf("encode message: %v", err)
	}
	if err := conn.WriteMessage(buf.Bytes()); err != nil {
		return fmt.Errorf("write message: %v", err)
	}

	// Flush
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("write deadline: %v", err)
	}
	_, err := conn.Flush()
	return err
}

func handleInits(conn *brontide.Conn) error {
	initMsg, err := recvMsg[*lnwire.Init](conn)
	if err != nil {
		return fmt.Errorf("init message: %v", err)
	}

	// Echo back the same init message to ensure compatibility.
	return sendMsg(conn, initMsg)
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	log.Println("Starting lnd fuzzing scenario...")

	// Create smite runner
	runner, err := smite.NewStdRunner()
	check(err)
	defer runner.Close()

	// Initialize daemon manager
	dm, err := NewDaemonManager()
	check(err)
	defer dm.Cleanup()

	// Start bitcoind
	if err := dm.startBitcoind(); err != nil {
		fmt.Printf("Failed to start bitcoind: %v\n", err)
		return
	}

	// Start lnd
	if err := dm.startLnd(); err != nil {
		fmt.Printf("Failed to start lnd: %v\n", err)
		return
	}

	log.Println("Both daemons are running, ready to fuzz")

	// Get lnd's address
	victim, err := dm.getLndAddr()
	if err != nil {
		runner.Fail(fmt.Sprintf("Failed to get lnd address: %v", err))
		return
	}

	// Try to connect to lnd
	conn, _, err := connect(victim)
	if err != nil {
		// Connection failure is expected with random keys
		log.Printf("Connection failed (expected): %v", err)
		runner.Skip()
		return
	}
	defer conn.Close()

	// Handle init messages
	if err := handleInits(conn); err != nil {
		log.Printf("Init handshake failed: %v", err)
		runner.Skip()
		return
	}

	log.Println("Successfully connected to lnd")

	// Get fuzz input and take snapshot
	fuzzInput := runner.GetFuzzInput()
	log.Printf("Received %d bytes of fuzz input", len(fuzzInput))

	// Write the whole fuzz input into the connection.
	conn.WriteMessage(fuzzInput)
	if err := conn.SetWriteDeadline(time.Now().Add(timeout)); err != nil {
		return
	}
	conn.Flush()

	lndDataDir := filepath.Join(dm.dataDir, "lnd")
	// Call `GetInfo()` rpc to trigger the copying of the coverage map.
	// TODO: using the `lncli` tool is really slow.
	cmd := exec.Command("lncli",
		"--lnddir="+lndDataDir,
		"--rpcserver="+lndHost+":"+lndRPCPort,
		"--network=regtest",
		"getinfo",
	)
	if err := cmd.Run(); err != nil {
		runner.Fail("GetInfo failed, lnd might be dead")
		return
	}

	log.Println("Fuzzing iteration complete")
}
