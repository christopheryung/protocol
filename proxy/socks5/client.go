package main

import (
	"fmt"
	"log"
	"net"

	"github.com/txthinking/socks5"
)

func main() {
  dialer := net.Dialer{}
  // negotiate about auth method
  conn, err := negotiateAndAuth(dialer) 
  if err != nil {
    log.Fatal(err)
  }
  
  fmt.Println(conn)
}

func negotiateAndAuth(dialer net.Dialer) (net.Conn, error) {
  conn, err := dialer.Dial("tcp", "5.42.99.137:10100")
  if err != nil {
    log.Fatal(err)
  }
  // multiple auth methods can be used here
  req := socks5.NewNegotiationRequest([]byte{socks5.MethodUsernamePassword})
  _, err = req.WriteTo(conn)
  if err != nil {
    conn.Close()
    log.Fatal(err)
  }

  resp, err := socks5.NewNegotiationReplyFrom(conn)
  if err != nil {
    conn.Close()
    return nil, err
  }

  if resp.Method == socks5.MethodUsernamePassword {
    req := socks5.NewUserPassNegotiationRequest([]byte("test"), []byte("test"))
    _, err = req.WriteTo(conn)
    if err != nil {
      conn.Close()
      return nil, err
    }
    resp, err := socks5.NewUserPassNegotiationReplyFrom(conn)
    if err != nil {
      conn.Close()
      return nil, err
    }

    if resp.Status != socks5.UserPassStatusSuccess {
      conn.Close()
      return nil, socks5.ErrUserPassAuth
    }
  }

  return conn, nil
}
