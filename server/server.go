package main

import (
	"fmt"
	"log"
	"net"
	"slices"

	"github.com/txthinking/socks5"
)

type SocksServer struct {
  Addr string
  Username []byte
  Password []byte
}

func main() {
  server := newSocksServer("5.42.99.137:10100", []byte("test"), []byte("test"))
  listener, err := net.Listen("tcp", "0.0.0.0:10100")
  if err != nil {
    log.Fatal(err)
  }
  defer listener.Close()

  server.ListenAndServe(listener)
}

func newSocksServer(addr string, username []byte, password []byte) *SocksServer {
  s := &SocksServer{
    Addr: addr,
    Username: username,
    Password: password,
  }
  return s
}

func (s *SocksServer) ListenAndServe(listener net.Listener) error {
  for {
    conn, err := listener.Accept()
    if err != nil {
      log.Fatal(err)
    }

    s.negotiateAndAuth(conn)
  }
}

func (s *SocksServer) negotiateAndAuth(conn net.Conn) error {
  req, err := socks5.NewNegotiationRequestFrom(conn)
  if err != nil {
    conn.Close()
    log.Fatal(err)
  }
  fmt.Println("neg req:", req)
  
  for _, meth := range req.Methods {
    if meth == socks5.MethodNone {
      resp := socks5.NewNegotiationReply(socks5.MethodNone)
      _, err = resp.WriteTo(conn)
      if err != nil {
        conn.Close()
        log.Fatal(err)
      }
    }
  } 
 
  resp := socks5.NewNegotiationReply(socks5.MethodUsernamePassword)
  _, err = resp.WriteTo(conn)
  if err != nil {
    conn.Close()
    log.Fatal(err)
  }
  fmt.Println("neg resp", resp) 

  authReq, err := socks5.NewUserPassNegotiationRequestFrom(conn)
  if err != nil {
    conn.Close()
    log.Fatal(err)
  }
  fmt.Println("auth req:", authReq)
  // develop auth function later
  if slices.Equal(authReq.Uname, s.Username) && slices.Equal(authReq.Passwd, s.Password) {
    authResp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess)
    _, err := authResp.WriteTo(conn)
    if err != nil {
      log.Fatal(err)
      return err
    }
  } else {
    authResp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure)
    _, err := authResp.WriteTo(conn)
    log.Fatal(err)
    return err
  }

  return nil
}
