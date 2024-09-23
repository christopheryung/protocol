package main

import (
	"fmt"
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

  log.Println("Server is listening on", listener.Addr())
  server.ListenAndServe(listener)
}

func newServer(addr net.Addr, username []byte, password []byte, tcpTimeout int, udpTimeout int) *Server {
  return &Server{
    ServerAddr: addr,
    Username: username,
    Password: password,
    TCPTimeout: tcpTimeout,
    UDPTimeout: udpTimeout,
  }
}

func (s *Server) ListenAndServe(listener net.Listener) error {
  for {
    conn, err := listener.Accept()
    if err != nil {
      log.Println(err)
      continue
    }
    go s.handle(conn)
  }

}

func (s *Server) negotiateAndAuth(conn net.Conn) error {
  req, err := socks5.NewNegotiationRequestFrom(conn)
  if err != nil {
    return err
  }
  
  var methodSelected byte
  for _, meth := range req.Methods {
    if meth == socks5.MethodUsernamePassword {
      methodSelected = socks5.MethodUsernamePassword
      break
    }
  }

  resp := socks5.NewNegotiationReply(methodSelected)
  if _, err = resp.WriteTo(conn); err != nil {
    return err
  }

  authReq, err := socks5.NewUserPassNegotiationRequestFrom(conn)
  if err != nil {
    return err
  }

  // develop auth function later
  if slices.Equal(authReq.Uname, s.Username) && slices.Equal(authReq.Passwd, s.Password) {
    authResp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusSuccess)
    _, err := authResp.WriteTo(conn)
    return err
  } else {
    authResp := socks5.NewUserPassNegotiationReply(socks5.UserPassStatusFailure)
    _, err := authResp.WriteTo(conn)
    return err
  }
}

func (s *Server) handle(conn net.Conn) {
  if err := s.negotiateAndAuth(conn); err != nil {
    log.Println("Auth failed: ", err)
    return
  }

  req, err := socks5.NewRequestFrom(conn)
  if err != nil {
    log.Println("Error reading request: ", err)
  }

  fmt.Println(req.Cmd)
  switch req.Cmd {
  case socks5.CmdConnect:
    fmt.Println("God TCP request")
    s.handleTCP(conn, req)
  case socks5.CmdUDP:
    fmt.Println("Got UDP request")
  default:
    log.Println("Unsupported command")
    resp := socks5.NewReply(socks5.RepCommandNotSupported, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
    resp.WriteTo(conn)
  }

}

func (s *Server) handleTCP(conn net.Conn, req *socks5.Request) {
  destConn, err := net.Dial("tcp", req.Address())
  if err != nil {
    log.Println("Error connectin to dest", err)
    resp := socks5.NewReply(socks5.RepHostUnreachable, socks5.ATYPIPv4, []byte{0, 0, 0, 0}, []byte{0, 0})
    resp.WriteTo(conn)
    return
  }
  defer destConn.Close()

  resp := socks5.NewReply(socks5.RepSuccess, socks5.ATYPIPv4, []byte{0x00, 0x00, 0x00, 0x00}, []byte{0x00, 0x00})
  if _, err := resp.WriteTo(conn); err != nil {
    log.Println("Error sending reply", err)
    return
  }

  go func() {
    _, err := io.Copy(destConn, conn)
    if err != nil {
      log.Println("Error cp to dst", err)
    }
  }()

  _, err = io.Copy(conn, destConn)
  if err != nil {
    log.Println("Error cp to client", err)
  }
}
