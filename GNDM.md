# golang 网络编程

## 0.01 ICMP协议

### 官方icmp包

~~~go
golang.org/x/net/icmp
~~~

### icmp.ListenPacket

~~~go
func ListenPacket(network string, address string) (*PacketConn, error)
~~~

ListenPackage 监听地址为address传入的icmp包，

对于非root权限数据包的端点，network字段必须为udp4或upd6。 端点允许读取、写入一些有限的ICMP消息，例如echo饿request和reply。目前只有MacOS和Linux支持这个函数。对于有原始特权的icmp端点，network字段必须为ip4或ip6，后面跟:和icmp协议编号。

使用上，可以忽略udp4/6，只用ip4:icmp和ip6:ipv6-icmp,这个包监测的是响应，举个例子

A使用这个包，A去pingB ，如果B有响应回来，那么就会得到PacketConn，如果B没有响应，则无返回数据。

![image-20211115172002004](https://image.perng.cn/image20220809013512.png)

 

## 0.02 HTTP

### http/http2 官方包

~~~go
net/http
~~~

#### http.ListenAndServe

~~~go
func ListenAndServe(addr string, handler Handler) error
~~~

入参本地监听端口以及处理器,会开启一个本地服务，并将服务接收请求交给handler去处理

举个例子

~~~go
http.ListenAndServe(":8080", Indexhandler)
~~~

#### http.ListenAndServeTLS

~~~go
func ListenAndServeTLS(addr string, certFile string, keyFile string, handler Handler) error
~~~



与http.ListenAndServe类似，但新增了证书与key参数，用以开启https/tls服务,注意，cert与key并不是某变量，而是两个绝对路径。

举个例子

~~~go
err := http.ListenAndServeTLS(":10443", "cert.pem", "key.pem", indexhandler)
~~~

### http3 

#### 扩展包

~~~url
github.com/lucas-clemente/quic-go
~~~

#### http3.ListenAndServe

~~~go
func ListenAndServe(addr string, certFile string, keyFile string, handler http.Handler) err
~~~

用法与http.ListenAndServeTLS相同,用来开启http3

#### http3.ListenAndServeQUIC

~~~go
func ListenAndServeQUIC(addr string, certFile string, keyFile string, handler http.Handler) err
~~~

用法与http3.ListenAndServe相同,用来开启http3的QUIC支持



## 0.03 TLS

### TLSConfig

#### ClientAuth 

~~~golang
clientAuth := tls.NoCLientCert
~~~

ClientAuth有五种类型，分别是 NoClientCert、RequestClientCert、RequireAnyClientCert、VerifyClientCertIfGiven、RequireAndVerifyClientCert，各自的含义是：

    NoClientCert：忽略任何客户端证书，即客户端可以不提供证书。
    RequestClientCert：要求客户端提供证书，但是如果客户端没有提供证书，服务端还是会继续处理请求。
    RequireAnyClientCert：需要客户端提供证书，但不用ClientCA来验证证书的有效性。
    VerifyClientCertIfGiven：如果客户端提供了证书，则用ClientCA来验证证书的有效性。 如果客户端没提供，则会继续处理请求。
    RequireAndVerifyClientCert：需要客户端提供证书，且会用ClientCA来验证证书的有效性。

#### 客户端加载证书

~~~
	conf := &tls.Config{
		//将证书载入客户端的tlsconfig
		Certificates: []tls.Certificate{caCrt},
	}
~~~

### 客户端忽略证书

```go
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
```



## net.DialIP

### network

支持如下

- ICMP
- ARP
