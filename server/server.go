package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/gob"
	"github.com/kungze/quic-tun/pkg/constants"
	"github.com/kungze/quic-tun/pkg/log"
	"github.com/kungze/quic-tun/pkg/token"
	"github.com/kungze/quic-tun/pkg/tunnel"
	"github.com/lucas-clemente/quic-go"
	"io"
	"net"
	"strings"
)

type ServerEndpoint struct {
	Address     string
	TlsConfig   *tls.Config
	TokenParser token.TokenParserPlugin
}

var SendCh chan tunnel.UdpMsg
var ClientAppAddrList map[string]string
var ClientAppChList map[string]chan tunnel.UdpMsg

func (s *ServerEndpoint) Start() {
	// Listen a quic(UDP) socket.
	cfg := &quic.Config{
		EnableDatagrams: true,
	}
	listener, err := quic.ListenAddr(s.Address, s.TlsConfig, cfg)
	if err != nil {
		panic(err)
	}
	SendCh = make(chan tunnel.UdpMsg)
	defer close(SendCh)
	ClientAppAddrList = make(map[string]string)
	ClientAppChList = make(map[string]chan tunnel.UdpMsg)

	defer listener.Close()
	log.Infow("Server endpoint start up successful", "listen address", listener.Addr())
	for {
		ctx, cancel := context.WithCancel(context.Background())
		// Wait client endpoint connection request.
		session, err := listener.Accept(context.Background())
		if err != nil {
			log.Errorw("Encounter error when accept a connection.", "error", err.Error())
		} else {
			parent_ctx := context.WithValue(context.TODO(), constants.CtxRemoteEndpointAddr, session.RemoteAddr().String())
			logger := log.WithValues(constants.ClientEndpointAddr, session.RemoteAddr().String())
			logger.Info("A new client endpoint connect request accepted.")
			//监听quic的stream消息，并发送到tcp
			go func() {
				for {
					// Wait client endpoint open a stream (A new steam means a new tunnel)
					stream, err := session.AcceptStream(context.Background())
					if err != nil {
						logger.Errorw("Cannot accept a new stream.", "error", err.Error())
						break
					}
					logger := logger.WithValues(constants.StreamID, stream.StreamID())
					ctx := logger.WithContext(parent_ctx)
					hsh := tunnel.NewHandshakeHelper(constants.AckMsgLength, handshake)
					hsh.TokenParser = &s.TokenParser

					tun := tunnel.NewTunnel(&stream, constants.ServerEndpoint)
					tun.Hsh = &hsh
					if !tun.HandShake(ctx) {
						continue
					}
					// After handshake successful the server application's address is established we can add it to log
					ctx = logger.WithValues(constants.ServerAppAddr, (*tun.Conn).RemoteAddr().String()).WithContext(ctx)
					go tun.Establish(ctx)
				}
			}()

			defer cancel()
			//监听quic的datagram消息，并发送到UDP
			go readMsgFromDatagram(ctx, session)
		}
		go sendMsgToDatagram(ctx, session)
	}
}

func handshake(ctx context.Context, stream *quic.Stream, hsh *tunnel.HandshakeHelper) (bool, *net.Conn) {
	logger := log.FromContext(ctx)
	logger.Info("Starting handshake with client endpoint")
	if _, err := io.CopyN(hsh, *stream, constants.TokenLength); err != nil {
		logger.Errorw("Can not receive token", "error", err.Error())
		return false, nil
	}
	addr, err := (*hsh.TokenParser).ParseToken(hsh.ReceiveData)
	if err != nil {
		logger.Errorw("Failed to parse token", "error", err.Error())
		hsh.SetSendData([]byte{constants.ParseTokenError})
		_, _ = io.Copy(*stream, hsh)
		return false, nil
	}
	logger = logger.WithValues(constants.ServerAppAddr, addr)
	logger.Info("starting connect to server app")
	sockets := strings.Split(addr, ":")
	conn, err := net.Dial(strings.ToLower(sockets[0]), strings.Join(sockets[1:], ":"))
	if err != nil {
		logger.Errorw("Failed to dial server app", "error", err.Error())
		hsh.SetSendData([]byte{constants.CannotConnServer})
		_, _ = io.Copy(*stream, hsh)
		return false, nil
	}
	logger.Info("Server app connect successful")
	hsh.SetSendData([]byte{constants.HandshakeSuccess})
	if _, err = io.CopyN(*stream, hsh, constants.AckMsgLength); err != nil {
		logger.Errorw("Faied to send ack info", "error", err.Error(), "", hsh.SendData)
		return false, nil
	}
	logger.Info("Handshake successful")
	return true, &conn
}

func Msg2ByteArr(buf bytes.Buffer, enc *gob.Encoder, msg tunnel.UdpMsg) []byte {
	buf.Reset()
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

func readMsgFromDatagram(ctx context.Context, session quic.Session) {
	for {
		select {
		case <-ctx.Done():
			log.Info("Received context cancellation. Exiting goroutine: readMsgFromDatagram")
			return
		default:
			log.Info("====1、从datagram读取数据====")
			//监听datagram消息
			data, err := session.ReceiveMessage()
			if err != nil {
				log.Errorf("Receive datagram msg failed! err: %s", err.Error())
				return
			}
			if data != nil {
				var msg tunnel.UdpMsg
				n := len(data)
				dec := gob.NewDecoder(bytes.NewReader(data[:n]))
				err := dec.Decode(&msg)
				if err != nil {
					log.Errorf("Decode message failed! err: %S", err.Error())
					return
				}
				log.Infof("====1、message====%s", string(msg.Message))
				clientIp := msg.Local
				serverIp := msg.Remote
				res, ok := ClientAppAddrList[clientIp]
				if !ok || serverIp != res {
					log.Info("====1.1、新建channel,写入数据====")
					//新增/更新地址map记录、channel、channel记录
					ClientAppAddrList[clientIp] = serverIp
					channelA := make(chan tunnel.UdpMsg)
					ClientAppChList[clientIp] = channelA
					ctx1 := context.Background()
					go readMsgFromUdpServer(ctx1, clientIp)
					channelA <- msg

				} else {
					log.Info("====1.2、已有channel,写入数据====")
					channelA, ok := ClientAppChList[clientIp]
					if !ok {
						log.Info("====1.2、获取channel失败====")
					}
					channelA <- msg
				}
			}
		}
	}
}

func sendMsgToDatagram(ctx context.Context, session quic.Session) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	for {
		select {
		case msg := <-SendCh:
			log.Info("====3、消息写入datagram====")
			//消息编码
			err := enc.Encode(msg)
			if err != nil {
				log.Fatalf("Encode message failed! err: %s", err.Error())
			}
			err = session.SendMessage(buf.Bytes())
			if err != nil {
				log.Fatalf("Send message to datagram failed! err: %s", err.Error())
				return
			}
			log.Infof("====3、message:%s====", string(msg.Message))
		case <-ctx.Done():
			log.Info("Received context cancellation. Exiting goroutine: sendMsgToDatagram")
			return
		}
	}
}

func readMsgFromUdpServer(ctx context.Context, clientIp string) {
	log.Info("====2、从datagram读取数据写入udp server,读取Udp server数据并写入SendCh====")
	serverIp := ClientAppAddrList[clientIp]
	channelA := ClientAppChList[clientIp]
	udpAddr, err := net.ResolveUDPAddr("udp", serverIp)
	if err != nil {
		delete(ClientAppAddrList, clientIp)
		delete(ClientAppChList, clientIp)
		close(channelA)
		log.Error("ResolveUDPAddr failed!")
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		delete(ClientAppAddrList, clientIp)
		delete(ClientAppChList, clientIp)
		close(channelA)
		log.Error("DialUDP failed!")
		return
	}
	//defer udpConn.Close()

	buffer := make([]byte, 4096)
	go func() {
		for {
			select {
			case <-ctx.Done():
				delete(ClientAppAddrList, clientIp)
				delete(ClientAppChList, clientIp)
				close(channelA)
				log.Info("Received context cancellation. Exiting goroutine: readMsgFromUdpServer")
				return
			case msg := <-channelA:
				log.Info("====2.1读取datagram数据，写入udp server====")
				//(从datagram)接收到channel消息发送给udp_server
				data := msg.Message
				log.Infof("====2.1 message====:%S", string(data))
				_, err := udpConn.Write(data)
				if err != nil {
					log.Error("Write to UDP failed!")
					return
				}
			}
		}
	}()

	go func() {
		for {
			n, err := udpConn.Read(buffer)
			if err != nil {
				log.Errorf("Read from UDP failed!%s", err.Error())
				continue
			}
			log.Infof("====2.2读取Udp server数据，传入通道SendCh====")
			//监听到udp服务器消息，构造后发送给SendCh
			msg := tunnel.UdpMsg{
				Local:   clientIp,
				Remote:  serverIp,
				Message: buffer[:n],
			}
			SendCh <- msg
		}
	}()
}
