package main

import (
	"io"
	"log"
	"net"
	"slices"

	"github.com/txthinking/socks5"
)

type Server struct {
  ServerAddr net.Addr
  Username []byte
  Password []byte
  TCPTimeout int
  UDPTimeout int
}


func main() {
  serverAddr, err := net.ResolveTCPAddr("tcp", "5.42.99.137:10100")
  if err != nil {
    log.Fatal(err)
  }
  server := newServer(serverAddr, []byte("test"), []byte("test"), 0, 0)

  listener, err := net.Listen("tcp", "0.0.0.0:10100")
  if err != nil {
    log.Fatal(err)
  }
  server.ListenAndServe(listener)
}

func newServer(addr net.Addr, username []byte, password []byte, tcpTimeout int, udpTimeout int) *Server {
  s := &Server{
    ServerAddr: addr,
    Username: username,
    Password: password,
    TCPTimeout: tcpTimeout,
    UDPTimeout: udpTimeout,
  }
  return s
}

func (s *Server) ListenAndServe(listener net.Listener) error {
  for {
    conn, err := listener.Accept()
    if err != nil {
      return err
    }

    go s.handle(conn)
  }

}

func (s *Server) negotiateAndAuth(conn net.Conn) error {
  req, err := socks5.NewNegotiationRequestFrom(conn)
  if err != nil {
    conn.Close()
    log.Fatal(err)
  }
  
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

  authReq, err := socks5.NewUserPassNegotiationRequestFrom(conn)
  if err != nil {
    conn.Close()
    log.Fatal(err)
  }

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

func (s *Server) handle(conn net.Conn) {
  s.negotiateAndAuth(conn)

  req, err := socks5.NewRequestFrom(conn)
  if err != nil {
    conn.Close()
    log.Fatal()
  }

  switch req.Cmd {
  case socks5.CmdConnect:
    s.handleTCP(conn, req)
  }

}

func (s *Server) handleTCP(conn net.Conn, req *socks5.Request) {

  destConn, err := net.Dial("tcp", req.Address())
  if err != nil {
    log.Fatal(err)
  }

  defer destConn.Close()

  resp := socks5.NewReply(socks5.RepSuccess, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})

  if _, err := resp.WriteTo(conn); err != nil {
    log.Fatal(err)
  }

  go func() {
    _, err := io.Copy(destConn, conn)
    if err != nil {
      log.Fatal(err)
    }
  }()

  _, err = io.Copy(conn, destConn)
  if err != nil {
    log.Fatal(err)
  }
}
