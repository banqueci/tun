package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/gob"
	"fmt"
	"github.com/kungze/quic-tun/pkg/constants"
	"github.com/kungze/quic-tun/pkg/log"
	"github.com/kungze/quic-tun/pkg/token"
	"github.com/kungze/quic-tun/pkg/tunnel"
	"github.com/lucas-clemente/quic-go"
	"io"
	"net"
	"strings"
	"sync"
)

type ClientEndpoint struct {
	LocalSocket          string
	ServerEndpointSocket string
	TokenSource          token.TokenSourcePlugin
	TlsConfig            *tls.Config
}

var ClientAppAddrList map[string]*net.UDPAddr
var ServerAppAddr string

func (c *ClientEndpoint) Start() {
	// Dial server endpoint
	session, err := quic.DialAddr(c.ServerEndpointSocket, c.TlsConfig, &quic.Config{KeepAlive: true, EnableDatagrams: true})
	if err != nil {
		fmt.Println("err:", err)
		panic(err)
	}
	parent_ctx := context.WithValue(context.TODO(), constants.CtxRemoteEndpointAddr, session.RemoteAddr().String())

	localSocket := strings.Split(c.LocalSocket, ":")
	protocol := strings.ToLower(localSocket[0])
	ServerAppAddr = "127.0.0.1:8090"
	//ServerAppAddr = strings.Join(localSocket[1:], ":")
	fmt.Println("===========ServerAppAddr===", ServerAppAddr)
	if strings.HasPrefix(protocol, "tcp") || protocol == "unix" || protocol == "unixpacket" {
		// Listen on a TCP or UNIX socket, wait client application's connection request.
		listener, err := net.Listen(protocol, strings.Join(localSocket[1:], ":"))
		if err != nil {
			panic(err)
		}
		defer listener.Close()
		log.Infow("Client endpoint start up successful", "listen address", listener.Addr())
		for {
			// Accept client application connectin request
			conn, err := listener.Accept()
			if err != nil {
				log.Errorw("Client app connect failed", "error", err.Error())
			} else {
				logger := log.WithValues(constants.ClientAppAddr, conn.RemoteAddr().String())
				logger.Info("Client connection accepted, prepare to entablish tunnel with server endpint for this connection.")
				go func() {
					defer func() {
						conn.Close()
						logger.Info("Tunnel closed")
					}()
					// Open a quic stream for each client application connection.
					stream, err := session.OpenStreamSync(context.Background())
					if err != nil {
						logger.Errorw("Failed to open stream to server endpoint.", "error", err.Error())
						return
					}
					defer stream.Close()
					logger = logger.WithValues(constants.StreamID, stream.StreamID())
					// Create a context argument for each new tunnel
					ctx := context.WithValue(
						logger.WithContext(parent_ctx),
						constants.CtxClientAppAddr, conn.RemoteAddr().String())
					hsh := tunnel.NewHandshakeHelper(constants.TokenLength, handshake)
					hsh.TokenSource = &c.TokenSource
					// Create a new tunnel for the new client application connection.
					tun := tunnel.NewTunnel(&stream, constants.ClientEndpoint)
					tun.Conn = &conn
					tun.Hsh = &hsh
					if !tun.HandShake(ctx) {
						return
					}
					tun.Establish(ctx)
				}()
			}
		}
	}
	if strings.HasPrefix(protocol, "udp") {
		// Listen on a UDP, wait client application's connection request.
		str := strings.Join(localSocket[1:], ":")
		address, err1 := net.ResolveUDPAddr(protocol, str)
		if err1 != nil {
			panic(err1)
		}
		udpConn, err := net.ListenUDP(protocol, address)
		if err != nil {
			log.Errorw("Client app connect failed", "error", err.Error())
		} else {
			//只有当有客户端连接时才继续执行
			logger := log.WithValues(constants.ClientAppAddr, "udp client")
			defer func() {
				udpConn.Close()
				logger.Info("Tunnel closed")
			}()

			ClientAppAddrList = make(map[string]*net.UDPAddr)

			var wg sync.WaitGroup
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			//循环：从udp连接中读取数据并写入datagram
			wg.Add(1)
			go udp2Datagram(ctx, udpConn, session, logger, &wg)

			//循环：从datagram中读取数据并写入udp连接
			wg.Add(1)
			go datagram2Udp(ctx, udpConn, session, logger, &wg)

			wg.Wait()

		}
	}
}

func handshake(ctx context.Context, stream *quic.Stream, hsh *tunnel.HandshakeHelper) (bool, *net.Conn) {
	logger := log.FromContext(ctx)
	logger.Info("Starting handshake with server endpoint")
	token, err := (*hsh.TokenSource).GetToken(fmt.Sprint(ctx.Value(constants.CtxClientAppAddr)))
	if err != nil {
		logger.Errorw("Encounter error.", "erros", err.Error())
		return false, nil
	}
	hsh.SetSendData([]byte(token))
	_, err = io.CopyN(*stream, hsh, constants.TokenLength)
	if err != nil {
		logger.Errorw("Failed to send token", err.Error())
		return false, nil
	}
	_, err = io.CopyN(hsh, *stream, constants.AckMsgLength)
	if err != nil {
		logger.Errorw("Failed to receive ack", err.Error())
		return false, nil
	}
	switch hsh.ReceiveData[0] {
	case constants.HandshakeSuccess:
		logger.Info("Handshake successful")
		return true, nil
	case constants.ParseTokenError:
		logger.Errorw("handshake error!", "error", "server endpoint can not parser token")
		return false, nil
	case constants.CannotConnServer:
		logger.Errorw("handshake error!", "error", "server endpoint can not connect to server application")
		return false, nil
	default:
		logger.Errorw("handshake error!", "error", "received an unknow ack info")
		return false, nil
	}
}

func udp2Datagram(ctx context.Context, conn *net.UDPConn, session quic.Session, logger log.Logger, wg *sync.WaitGroup) {
	defer wg.Done()
	var buf1 bytes.Buffer
	enc := gob.NewEncoder(&buf1)

	buf := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			//监听客户端消息
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				logger.Errorf("Receive udp msg failed! err: %s", err.Error())
			}
			//记录客户端ip-addr
			_, ok := ClientAppAddrList[addr.IP.String()]
			if !ok {
				ClientAppAddrList[addr.IP.String()] = addr

			}
			//构造消息
			msg := tunnel.UdpMsg{
				Local:   addr.IP.String(),
				Remote:  ServerAppAddr,
				Message: buf[:n],
			}
			//消息编码
			err = enc.Encode(msg)
			if err != nil {
				log.Fatalf("Encode message failed! err: %s", err.Error())
			}
			res := buf1.Bytes()
			//res := Msg2ByteArr(buf1, enc, msg)
			//发送
			err = session.SendMessage(res)
			if err != nil {
				logger.Errorf("Send msg to datagram failed! err: %s", err.Error())
			}

			logger.Infof("Forward message to Quic server, buf[:n]:%s", string(buf[:n]))
			logger.Infof("Forward message to Quic server, res:%s", buf1.String())
		}
	}

}

func datagram2Udp(ctx context.Context, conn *net.UDPConn, session quic.Session, logger log.Logger, wg *sync.WaitGroup) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		default:
			//监听datagram消息
			data, err := session.ReceiveMessage()
			if err != nil {
				logger.Errorf("Receive datagram msg failed! err: %s", err.Error())
				return
			}
			if data != nil {
				//解码
				//msg := ByteArr2Msg(data)
				var msg tunnel.UdpMsg
				n := len(data)
				dec := gob.NewDecoder(bytes.NewReader(data[:n]))
				err := dec.Decode(&msg)
				if err != nil {
					logger.Errorf("Decode message failed! err: %S", err.Error())
					return
				}
				//查询udp客户端地址
				clientIp := msg.Local
				addr, ok := ClientAppAddrList[clientIp]
				if !ok {
					logger.Errorf("Can't find udp_client addr! err: %S", err.Error())
				}
				//从构造消息中取回原消息
				buf := msg.Message
				m := len(buf)
				_, err = conn.WriteToUDP(buf, addr)
				if err != nil {
					logger.Errorf("Send message to Udp failed! err: %S", err.Error())
					return
				}
				logger.Infof("Forward message to Udp client, msg:%s", string(buf[:m]))
			}
		}
	}
}

func Msg2ByteArr(buf bytes.Buffer, enc *gob.Encoder, msg tunnel.UdpMsg) []byte {
	//buf.Reset()
	err := enc.Encode(msg)
	if err != nil {
		log.Fatalf("Encode message failed! err: %s", err.Error())
	}
	return buf.Bytes()
}

func ByteArr2Msg(data []byte) tunnel.UdpMsg {
	var msg tunnel.UdpMsg

	reader := bytes.NewReader(data)
	var buf bytes.Buffer
	_, err := buf.ReadFrom(reader)
	if err != nil {
		log.Fatalf("Conversion format failed! err: %s", err.Error())
	}

	dec := gob.NewDecoder(&buf)
	var res tunnel.UdpMsg
	err = dec.Decode(&msg)
	if err != nil {
		log.Fatalf("Decode message failed! err: %s", err.Error())
	}
	return res
}
