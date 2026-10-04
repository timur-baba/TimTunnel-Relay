package main

import (
    "bufio"
    "crypto/ed25519"
    "crypto/sha256"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/base64"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "io"
    "log"
    "math/big"
    "net"
    "os"
    "strings"
    "sync"
    "time"
)

const tunnelPreface = "TT1\n"

type Message struct {
    Type  string `json:"type"`
    Token string `json:"token,omitempty"`
    ID    string `json:"id,omitempty"`
    Error string `json:"error,omitempty"`
}

type PairingPayload struct {
    RelayAddress   string `json:"relay_address"`
    Token          string `json:"token"`
    TLSFingerprint string `json:"tls_fingerprint"`
}

type bufferedConn struct {
    net.Conn
    r *bufio.Reader
}
func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type activeAgent struct {
    conn net.Conn
    enc *json.Encoder
    mu sync.Mutex
}

type relayState struct {
    mu sync.Mutex
    agent *activeAgent
    pending map[string]net.Conn
    timeout time.Duration
}

func main() {
    log.SetFlags(log.LstdFlags | log.Lmicroseconds)
    port := firstNonEmpty(os.Getenv("PORT"), "7000")
    listen := "0.0.0.0:" + port

    token := strings.TrimSpace(os.Getenv("TT_TOKEN"))
    if token == "" {
        // Stable fallback for Railway so a restart does not invalidate pairing.
        basis := strings.Join([]string{
            "TimTunnel-Railway-v1.3",
            os.Getenv("RAILWAY_PROJECT_ID"),
            os.Getenv("RAILWAY_SERVICE_ID"),
            os.Getenv("RAILWAY_ENVIRONMENT_ID"),
        }, "|")
        sum := sha256.Sum256([]byte(basis))
        token = hex.EncodeToString(sum[:])
        log.Printf("[RELAY] TT_TOKEN tanimli degil; Railway kimliklerinden stabil token uretiliyor.")
    }

    cert, fp, err := deterministicCert(token)
    if err != nil { log.Fatal(err) }
    tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}

    ln, err := net.Listen("tcp", listen)
    if err != nil { log.Fatalf("listen: %v", err) }
    defer ln.Close()

    st := &relayState{pending: make(map[string]net.Conn), timeout: 15*time.Second}

    log.Printf("[RELAY] TimTunnel Railway Relay v1.3")
    log.Printf("[RELAY] Tek port dinleniyor: %s", listen)
    printPairingCode(token, fp)

    for {
        c, err := ln.Accept()
        if err != nil { log.Printf("accept: %v", err); continue }
        go st.handleIncoming(c, tlsCfg, token)
    }
}

func (st *relayState) handleIncoming(c net.Conn, tlsCfg *tls.Config, token string) {
    br := bufio.NewReaderSize(c, 4096)
    _ = c.SetReadDeadline(time.Now().Add(10*time.Second))
    p, err := br.Peek(len(tunnelPreface))
    if err == nil && string(p) == tunnelPreface {
        _, _ = br.Discard(len(tunnelPreface))
        _ = c.SetReadDeadline(time.Time{})
        wrapped := &bufferedConn{Conn: c, r: br}
        tc := tls.Server(wrapped, tlsCfg)
        if err := tc.Handshake(); err != nil { c.Close(); return }
        st.handleTLSConn(tc, token)
        return
    }
    _ = c.SetReadDeadline(time.Time{})
    st.handlePublic(&bufferedConn{Conn: c, r: br})
}

func (st *relayState) handleTLSConn(c net.Conn, token string) {
    dec := json.NewDecoder(c)
    var hello Message
    if err := dec.Decode(&hello); err != nil { c.Close(); return }
    if hello.Token != token {
        _ = json.NewEncoder(c).Encode(Message{Type:"error", Error:"unauthorized"})
        c.Close(); return
    }

    switch hello.Type {
    case "agent":
        ag := &activeAgent{conn:c, enc:json.NewEncoder(c)}
        st.mu.Lock()
        if st.agent != nil { st.agent.conn.Close() }
        st.agent = ag
        st.mu.Unlock()
        log.Printf("[RELAY] Agent baglandi: %s", c.RemoteAddr())
        _ = ag.enc.Encode(Message{Type:"ready"})
        for {
            var m Message
            if err := dec.Decode(&m); err != nil { break }
        }
        st.mu.Lock()
        if st.agent == ag { st.agent = nil }
        st.mu.Unlock()
        c.Close()
        log.Printf("[RELAY] Agent ayrildi")

    case "data":
        st.mu.Lock()
        pub := st.pending[hello.ID]
        if pub != nil { delete(st.pending, hello.ID) }
        st.mu.Unlock()
        if pub == nil { c.Close(); return }
        log.Printf("[RELAY] Session eslesti: %s", hello.ID)
        bridge(pub, c)

    default:
        c.Close()
    }
}

func (st *relayState) handlePublic(pub net.Conn) {
    st.mu.Lock(); ag := st.agent; st.mu.Unlock()
    if ag == nil {
        log.Printf("[RELAY] Oyuncu reddedildi (agent offline): %s", pub.RemoteAddr())
        pub.Close(); return
    }

    id := randomID(pub.RemoteAddr().String())
    st.mu.Lock(); st.pending[id] = pub; st.mu.Unlock()

    ag.mu.Lock()
    err := ag.enc.Encode(Message{Type:"open", ID:id})
    ag.mu.Unlock()
    if err != nil {
        st.mu.Lock(); delete(st.pending, id); st.mu.Unlock()
        pub.Close(); return
    }
    log.Printf("[RELAY] Yeni public baglanti %s -> %s", pub.RemoteAddr(), id)

    time.AfterFunc(st.timeout, func(){
        st.mu.Lock(); p := st.pending[id]; if p != nil { delete(st.pending,id) }; st.mu.Unlock()
        if p != nil { log.Printf("[RELAY] Session timeout: %s", id); p.Close() }
    })
}

func bridge(a, b net.Conn) {
    defer a.Close(); defer b.Close()
    done := make(chan struct{}, 2)
    go func(){ _,_ = io.Copy(a,b); done<-struct{}{} }()
    go func(){ _,_ = io.Copy(b,a); done<-struct{}{} }()
    <-done
}

func printPairingCode(token, fp string) {
    host := strings.TrimSpace(os.Getenv("RAILWAY_TCP_PROXY_DOMAIN"))
    extPort := strings.TrimSpace(os.Getenv("RAILWAY_TCP_PROXY_PORT"))
    if host == "" { host = strings.TrimSpace(os.Getenv("TT_PUBLIC_HOST")) }
    if extPort == "" { extPort = strings.TrimSpace(os.Getenv("TT_PUBLIC_PORT")) }
    if host == "" || extPort == "" {
        fmt.Println("\n============================================================")
        fmt.Println("TCP PROXY HENUZ YOK")
        fmt.Println("Railway -> Service -> Settings -> Networking -> TCP Proxy")
        fmt.Println("Internal/Application port olarak PORT degerini sec.")
        fmt.Println("Proxy olustuktan sonra servisi Redeploy et.")
        fmt.Println("============================================================\n")
        return
    }
    p := PairingPayload{RelayAddress: net.JoinHostPort(host,extPort), Token:token, TLSFingerprint:fp}
    b,_ := json.Marshal(p)
    code := "TT1-" + base64.RawURLEncoding.EncodeToString(b)
    fmt.Println("\n============================================================")
    fmt.Println("WINDOWS AGENT ESLESTIRME KODU")
    fmt.Println(code)
    fmt.Println("============================================================")
    fmt.Printf("Minecraft public adresi: %s:%s\n\n", host, extPort)
}

func deterministicCert(token string) (tls.Certificate, string, error) {
    seed := sha256.Sum256([]byte("TimTunnel-cert-v1|"+token))
    priv := ed25519.NewKeyFromSeed(seed[:])
    serial := new(big.Int).SetBytes(seed[:16])
    if serial.Sign() == 0 { serial = big.NewInt(1) }
    tmpl := x509.Certificate{
        SerialNumber: serial,
        Subject: pkix.Name{CommonName:"TimTunnel Railway Relay"},
        NotBefore: time.Date(2024,1,1,0,0,0,0,time.UTC),
        NotAfter: time.Date(2124,1,1,0,0,0,0,time.UTC),
        KeyUsage: x509.KeyUsageDigitalSignature,
        ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid:true,
    }
    der, err := x509.CreateCertificate(nil, &tmpl, &tmpl, priv.Public(), priv)
    if err != nil { return tls.Certificate{}, "", err }
    cert := tls.Certificate{Certificate:[][]byte{der}, PrivateKey:priv}
    sum := sha256.Sum256(der)
    return cert, strings.ToUpper(hex.EncodeToString(sum[:])), nil
}

func randomID(s string) string {
    sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%d", s, time.Now().UnixNano())))
    return hex.EncodeToString(sum[:12])
}
func firstNonEmpty(v,d string) string { if strings.TrimSpace(v)!="" { return strings.TrimSpace(v) }; return d }
