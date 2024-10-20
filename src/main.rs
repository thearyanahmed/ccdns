#[allow(unused_imports)]
use std::net::UdpSocket;

#[derive(Debug)]
struct MessageHeader {
    // Packet Identifier (ID)
    // 16 bits 
    // A random ID assigned to query packets. Response packets must reply with the same ID.
    id: u16,  

    // Query/Response Indicator (QR)
    // 1 bit
    // 1 for a reply packet, 0 for a question packet.
    qr: bool,

    // Operation Code (OPCODE)
    // 4 bits
    // Specifies the kind of query in a message. 
    opcode: u8,

    // Authoritative Answer (AA)
    // 1 bit
    // 1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    aa: bool,

    // Truncation (TC)
    // 1 bit
    // 1 if the message is larger than 512 bytes. Always 0 in UDP responses.  
    tc: bool,

    // Recursion Desired (RD)
    // 1 bit
    // 1 if the client wants the server to recursively resolve the query.  
    rd: bool,

    // Recursion Available (RA)
    // 1 bit
    // 1 if the server can recursively resolve the query. 
    ra: bool,

    // Reserved (Z)
    // 1 bit
    // Used by DNSSEC queries. At inception, it was reserved for future use. 
    z: u8,

    // Response Code
    // 4 bits
    // Response code indicating the status of the response. 
    rcode: u8,

    // QDCOUNT
    // 16 bits
    // Number of questions in the Question section. 
    qdcount: u16,

    // ANCOUNT
    // 16 bits
    // Number of resource records in the Answer section.
    ancount: u16,

    // NSCOUNT
    // 16 bits
    // Number of name server resource records in the Authority section.
    nscount: u16,

    // ARCOUNT
    // 16 bits
    // Number of resource records in the Additional section.
    arcount: u16,
}
impl Default for MessageHeader {
    fn default() -> Self {
        MessageHeader {
            id: 1234,
            qr: true,
            opcode: 0,
            aa: false,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: 0,
            qdcount: 0,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        }
    }
}


impl MessageHeader {
    fn to_bytes(&self) -> Vec<u8> {
    
        let mut dns_message_bytes = Vec::new();

        // Pack first byte (qr, opcode, aa, tc, rd)
        let mut byte1 = 0u8;
        byte1 |= (self.qr as u8) << 7;        // qr (1 bit)
        byte1 |= (self.opcode & 0xF) << 3;    // opcode (4 bits)
        byte1 |= (self.aa as u8) << 2;        // aa (1 bit)
        byte1 |= (self.tc as u8) << 1;        // tc (1 bit)
        byte1 |= self.rd as u8;               // rd (1 bit)

        // Pack second byte (ra, z, rcode)
        let mut byte2 = 0u8;
        byte2 |= (self.ra as u8) << 7;        // ra (1 bit)
        byte2 |= (self.z & 0x7) << 4;         // z (3 bits)
        byte2 |= self.rcode & 0xF;            // rcode (4 bits)

        // Add the packed bytes to the buffer
        dns_message_bytes.extend_from_slice(&self.id.to_be_bytes()); // ID (2 bytes)
        dns_message_bytes.push(byte1);        // Flags first byte
        dns_message_bytes.push(byte2);        // Flags second byte
        dns_message_bytes.extend_from_slice(&self.qdcount.to_be_bytes());
        dns_message_bytes.extend_from_slice(&self.ancount.to_be_bytes());
        dns_message_bytes.extend_from_slice(&self.nscount.to_be_bytes());
        dns_message_bytes.extend_from_slice(&self.arcount.to_be_bytes());

        dns_message_bytes
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.

    let header = MessageHeader::default();
    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];
    
    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let response = header.to_bytes();

                println!("Sending response: {:?}", response);
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
