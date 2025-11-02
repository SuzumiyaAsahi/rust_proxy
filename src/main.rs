use std::error::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
#[tokio::main]
async fn main() {
    start_server().await.unwrap();
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
    stream.flush().await?;
    // from here on, the real https data is exchanging between two streams
    let outbound = TcpStream::connect(addr.first().unwrap().as_str()).await?;
    let (mut inbound_reader, mut inbound_writer) = tokio::io::split(stream);
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
    let (mut inbound_reader, mut inbound_writer) = tokio::io::split(stream);
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
