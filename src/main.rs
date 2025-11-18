use rustls::{ClientConfig, RootCertStore};
use rustls_pemfile::Item;
use rustls_pki_types::{DnsName, PrivateKeyDer, ServerName};
use std::{
    error::Error,
    io::BufReader,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4, ToSocketAddrs},
    sync::Arc,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, rustls::ServerConfig};
#[path = "../my_cert/mod.rs"]
mod my_cert;
use my_cert::cert;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::main]
async fn main() {
    // start_server().await.unwrap();
    start_server().await.unwrap();
}

async fn start_socket5_sever() -> Result<(), Box<dyn Error>> {
    let listen = TcpListener::bind("127.0.0.1:7090").await?;
    loop {
        let (stream, addr) = listen.accept().await?;
        println!("{}", addr);
        tokio::spawn(async move {
            handle_socket5_client(stream).await.unwrap();
        });
    }
}

async fn handle_socket5_client(mut inbound: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0; 1024];
    let len = inbound.read(&mut buffer).await?;
    println!("{:?}", buffer[..len].to_vec());
    // client returns unathenticated respone
    inbound.write_all(&[5, 0]).await?;
    // because we choose unathentication, this step is skepped,
    // client will send request data.
    let mut buffer = [0; 1024];
    let len = inbound.read(&mut buffer).await?;
    println!("{:?}", buffer[..len].to_vec());
    // parse address
    let addr = match buffer[3] {
        // IPv4
        0x01 => {
            let host = u32::from_be_bytes(buffer[4..8].try_into().unwrap());
            let port = u16::from_be_bytes(buffer[8..10].try_into().unwrap());
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(host), port))
        }
        0x03 => {
            let len = buffer[4] as usize;
            let domain = String::from_utf8(buffer[5..len + 5].to_vec())?;
            let port = u16::from_be_bytes(buffer[len + 5..len + 7].try_into().unwrap());
            format!("{}:{}", domain, port)
                .to_socket_addrs()?
                .find(|x| x.is_ipv4())
                .ok_or("fail to parse IPv4 address")?
        }
        _ => {
            // here we respone a unsupported address type
            // 05 means version
            // 08 means Address type not supported
            // 00 means ipv4
            // 127,0,0,1:80 is meaningless
            inbound
                .write_all(&[5, 8, 0, 1, 127, 0, 0, 1, 0, 80])
                .await?;
            inbound.shutdown().await?;
            return Err("the type of address is not unsupported".into());
        }
    };
    println!("{}", addr);
    // establish connection and return data
    let outbound = match TcpStream::connect(addr).await {
        Ok(res) => res,
        Err(e) => {
            // fail to cnnect target address
            // 05 means Connection refused
            inbound
                .write_all(&[5, 5, 0, 1, 127, 0, 0, 1, 0, 80])
                .await?;
            inbound.shutdown().await?;
            return Err(e.into());
        }
    };
    // the second 00 means that connection succeeded.
    // 127,0,0,1:80 is also meaningless
    inbound
        .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
        .await?;
    // here we have finished the establishment of socks5 proxy.
    copy_io(inbound, outbound).await?;
    Ok(())
}

async fn start_server() -> Result<(), Box<dyn Error>> {
    let listen = TcpListener::bind("0.0.0.0:7090").await?;
    loop {
        let (stream, addr) = listen.accept().await?;
        println!("{}", addr);
        tokio::spawn(async move {
            handle_client_stream(stream).await.unwrap();
        });
    }
}

async fn handle_client_stream(mut stream: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0; 4096];
    let len = stream.read(&mut buffer).await?;
    // Convert all fileds to lowcase, because some clients are upcase, some are lowcase.
    if buffer.starts_with(b"CONNECT") {
        handle_https(stream, buffer, len).await?;
    } else {
        handle_http(stream, buffer, len).await?;
    }
    Ok(())
}

async fn handle_https(
    mut stream: TcpStream,
    buffer: [u8; 4096],
    len: usize,
) -> Result<(), Box<dyn Error>> {
    let info = String::from_utf8(buffer[..len].to_vec())?;
    let addr = regex_find("CONNECT (.*?) ", info.as_str())?;
    if addr.is_empty() {
        return Err("Fail to get real address".into());
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await?;
    // from here on, the real https data is exchanging between two streams
    let sni = addr[0].split(":").next().unwrap();
    let acceptor = gen_acceptor_for_sni(sni)?;
    let inbound = acceptor.accept(stream).await?;
    let mut root_ca = RootCertStore::empty();
    root_ca.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let client_config = ClientConfig::builder()
        .with_root_certificates(root_ca)
        .with_no_client_auth();
    let outbound = TcpStream::connect(&addr[0]).await?;
    let connector = TlsConnector::from(Arc::new(client_config));
    println!("{}", sni);
    let server_name = ServerName::DnsName(DnsName::try_from(sni.to_string())?);
    let outbound = connector.connect(server_name, outbound).await?;
    // //这里我们就实现了HTTPS解密，但是我们的根证书还没安装
    // //sudo cp sca.pem /etc/pki/ca-trust/source/anchors/
    // //sudo update-ca-trust
    copy_io(inbound, outbound).await?;
    Ok(())
}

async fn copy_io<I, O>(inbound: I, outbound: O) -> Result<(), Box<dyn Error>>
where
    I: AsyncReadExt + AsyncWriteExt + Send + Unpin + 'static,
    O: AsyncReadExt + AsyncWriteExt + Send + Unpin + 'static,
{
    let (mut inbound_reader, mut inbound_writer) = tokio::io::split(inbound);
    let (mut outbound_reader, mut outbound_writer) = tokio::io::split(outbound);
    let rt1 = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut inbound_reader, &mut outbound_writer).await;
    });
    let rt2 = tokio::spawn(async move {
        let _ = tokio::io::copy(&mut outbound_reader, &mut inbound_writer).await;
    });
    let _ = tokio::join!(rt1, rt2);
    Ok(())
}

async fn handle_http(
    stream: TcpStream,
    buffer: [u8; 4096],
    len: usize,
) -> Result<(), Box<dyn Error>> {
    // Convert all fileds to lowcase,
    // as some clients use uppercase and others lowcase
    let http_prefix = b"http://";
    let start_pos = buffer
        .windows(http_prefix.len())
        .position(|b| b == http_prefix)
        .ok_or("Fail to get HTTP address")?;
    let end_pos = buffer[start_pos + http_prefix.len()..len]
        .iter()
        .position(|b| *b == b'/')
        .ok_or("Fail to get HTTP address")?
        + start_pos
        + http_prefix.len();
    // Get true address of server, 80 port number will be omitted.
    let addr = String::from_utf8(buffer[start_pos + http_prefix.len()..end_pos].to_vec())?;
    println!("{:?}", addr);
    let host = addr.split(":").next().unwrap();
    let port = match addr.contains(":") {
        true => addr
            .split(":")
            .last()
            .ok_or("Fail to get port")?
            .parse::<u16>()?,
        false => 80,
    };
    // Here we get true address of server
    println!("{}: {}", host, port);
    // Establish connection to real server, and copy the two streams to each other.
    let mut outbound = TcpStream::connect(format!("{}:{}", addr, port)).await?;
    outbound.write_all(&buffer[..start_pos]).await?;
    outbound.write_all(&buffer[end_pos..len]).await?;
    copy_io(stream, outbound).await?;
    Ok(())
}

fn regex_find(rex: &str, context: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let regx = regex::RegexBuilder::new(rex).build()?;
    let mut res = vec![];
    for re in regx.captures_iter(context) {
        let mut r = vec![];
        for index in 0..re.len() {
            r.push(re[index].to_string());
        }
        if r.len() > 1 {
            r.remove(0);
        }
        res.extend(r);
    }
    Ok(res)
}

//这里需要实现一个TlsAcceptor才能解密
fn gen_acceptor_for_sni(sni: impl AsRef<str>) -> Result<TlsAcceptor, Box<dyn Error>> {
    //这里先要生成证书
    let (pem, key) = cert::gen_cert_for_sni(sni.as_ref(), "sca.pem", "sca.key")?;
    let ca_bs = pem.into_bytes();
    let key_bs = key.into_bytes();
    let mut reader = BufReader::new(ca_bs.as_slice());
    let item = rustls_pemfile::read_one(&mut reader)
        .transpose()
        .ok_or("读取证书失败")??;
    let sni_cert = match item {
        Item::X509Certificate(cert) => cert,
        _ => return Err("不支持的证书".into()),
    };
    let mut reader = BufReader::new(key_bs.as_slice());
    let item = rustls_pemfile::read_one(&mut reader)
        .transpose()
        .ok_or("读取证书密钥失败")??;
    let sni_key = match item {
        Item::Pkcs1Key(key) => PrivateKeyDer::Pkcs1(key),
        Item::Pkcs8Key(key) => PrivateKeyDer::Pkcs8(key),
        Item::Sec1Key(key) => PrivateKeyDer::Sec1(key),
        _ => return Err("不支持的证书密钥类型".into()),
    };
    let config = ServerConfig::builder_with_protocol_versions(&rustls::ALL_VERSIONS)
        .with_no_client_auth()
        .with_single_cert(vec![sni_cert], sni_key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    Ok(acceptor)
}
