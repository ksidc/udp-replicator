package main

import (
        "fmt"
        "net"
        "strings"
        "time"

        log "github.com/sirupsen/logrus"
        "gopkg.in/alecthomas/kingpin.v2"
)

var (
        debug      = kingpin.Flag("debug", "Enable debug mode").Envar("DEBUG").Bool()
        listenIP   = kingpin.Flag("listen-ip", "IP to listen in").Default("0.0.0.0").Envar("LISTEN_IP").IP()
        listenPort = kingpin.Flag("listen-port", "Port to listen on").Default("9000").Envar("LISTEN_PORT").Int()
        bodySize   = kingpin.Flag("body-size", "Size of body to read").Default("4096").Envar("BODY_SIZE").Int()

        forwards = kingpin.Flag("forward", "ip:port to forward traffic to (port defaults to listen-port)").PlaceHolder("ip:port").Envar("FORWARD").Strings()

        pretty = kingpin.Flag("pretty", "").Default("true").Envar("PRETTY").Hidden().Bool()

        targets []*net.UDPConn
        servers []string

        missing []string
)

func retry() {
        /*
        * When cannot dialup destination
        * Bekei
         */
        for {
                for i, forward := range missing {
                        // Resolve
                        addr, err := net.ResolveUDPAddr("udp", forward)
                        if err == nil {
                                // Setup conn
                                conn, err := net.DialUDP("udp", nil, addr)

                                if err != nil {
                                        log.Fatalf("Could not DialUDP: %+v (%s)", addr, err)
                                } else {
                                        targets = append(targets, conn)
                                        servers = append(servers, forward)
                                        missing = append(missing[:i], missing[i+1:]...)
                                }
                                defer conn.Close()
                        }

                }

                time.Sleep(time.Second)
                if len(missing) == 0 {
                        break
                }
        }
}

func resolve() {
        /*
        * reresolve destination address
        * Bekei
         */
        for {
                for i, forward := range servers {
                        addr, err := net.ResolveUDPAddr("udp", forward)
                        if err == nil {
                                if addr.String() != targets[i].RemoteAddr().String() {
                                        // Setup conn
                                        conn, err := net.DialUDP("udp", nil, addr)

                                        if err == nil {
                                                log.WithFields(log.Fields{
                                                        "before": addr,
                                                        "to":     conn.RemoteAddr(),
                                                }).Info("Forwarding target configured")
                                                targets[i].Close()
                                                targets[i] = conn
                                        }
                                        defer conn.Close()

                                }
                        }
                }
                time.Sleep(time.Second * 5)

        }
}

func main() {
        // CLI
        kingpin.Parse()

        // Log setup
        if *debug {
                log.SetLevel(log.DebugLevel)
        } else {
                log.SetLevel(log.InfoLevel)
        }
        if !*pretty {
                log.SetFormatter(&log.TextFormatter{
                        DisableColors: true,
                        FullTimestamp: true,
                })
        }

        if len(*forwards) <= 0 {
                log.Fatal("Must specify at least one forward target")
        }

        // Clients
        for _, forward := range *forwards {
                // Check for port
                if strings.Index(forward, ":") < 0 {
                        forward = fmt.Sprintf("%s:%d", forward, *listenPort)
                }

                // Resolve
                addr, err := net.ResolveUDPAddr("udp", forward)
                if err != nil {
                        missing = append(missing, forward)
                        log.Fatalf("Could not ResolveUDPAddr: %s (%s)", forward, err)
                } else {

                        // Setup conn
                        conn, err := net.DialUDP("udp", nil, addr)

                        if err != nil {
                                missing = append(missing, forward)
                                log.Fatalf("Could not DialUDP: %+v (%s)", addr, err)
                        } else {
                                targets = append(targets, conn)
                                servers = append(servers, forward)

                        }
                        defer conn.Close()
                }

        }

        // Server
        conn, err := net.ListenUDP("udp", &net.UDPAddr{
                Port: *listenPort,
                IP:   *listenIP,
        })
        if err != nil {
                log.Fatal(err)
        }

        defer conn.Close()

        // Startup status
        log.WithFields(log.Fields{
                "ip":   *listenIP,
                "port": *listenPort,
        }).Infof("Server started")
        for i, target := range targets {
                log.WithFields(log.Fields{
                        "num":   i + 1,
                        "total": len(targets),
                        "addr":  target.RemoteAddr(),
                }).Info("Forwarding target configured")
        }

        go retry()
        go resolve()

        for {
                // Read
                b := make([]byte, *bodySize)
                n, addr, err := conn.ReadFromUDP(b)
                if err != nil {
                        log.Error(err)
                        continue
                }

                // Log receive
                ctxLog := log.WithFields(log.Fields{
                        "source": addr.String(),
                        "body":   string(b[:n]),
                })
                ctxLog.Debugf("Recieved packet")

                // Proxy
                for _, target := range targets {
                        _, err := target.Write(b[:n])

                        // Log proxy
                        ctxLog := ctxLog.WithFields(log.Fields{
                                "target": target.RemoteAddr(),
                        })

                        if err != nil {
                                ctxLog.Warn("Could not forward packet", err)
                        } else {
                                ctxLog.Debug("Wrote to target")
                        }
                }
        }
}