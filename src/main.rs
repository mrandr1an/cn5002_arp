use libc::{close, if_nametoindex, recvfrom, sendto, sockaddr_ll, socket, AF_PACKET, SOCK_RAW};
use std::ffi::CString;
use std::mem;
use std::ptr;
use std::slice;

type Error = String;
type Response = Result<String, Error>;

trait Protocol {
    fn request(self, interface_name: String) -> Response;
}

#[repr(C, packed)]
struct EthernetFrame<P: Protocol> {
    dest_mac: [u8; 6],
    src_mac: [u8; 6],
    ethertype: u16,
    payload: P,
}

impl<P: Protocol> EthernetFrame<P> {
    fn new(packet: P, src_mac: [u8; 6], dest_mac: [u8; 6]) -> Self {
        EthernetFrame {
            dest_mac,
            src_mac,
            ethertype: 0x0806u16.to_be(), // ARP
            payload: packet,
        }
    }
}

#[repr(C, packed)]
pub struct ArpPacket {
    htype: u16,
    ptype: u16,
    hlen: u8,
    plen: u8,
    oper: u16,
    sha: [u8; 6],
    spa: [u8; 4],
    tha: [u8; 6],
    tpa: [u8; 4],
}

impl ArpPacket {
    fn new(oper: u16, sha: [u8; 6], spa: [u8; 4], tpa: [u8; 4]) -> Self {
        Self {
            htype: 1u16.to_be(),      // Ethernet
            ptype: 0x0800u16.to_be(), // IPv4
            hlen: 6,                  // Ethernet
            plen: 4,                  // IPv4
            oper: oper.to_be(),       // Operation
            sha,                      // Sender MAC
            spa,                      // Sender IP
            tha: [0; 6],              // Target MAC
            tpa,                      // Target IP
        }
    }
}

impl Protocol for ArpPacket {
    fn request(self, interface_name: String) -> Response {
        let src_mac = self.sha;
        let target_ip = self.tpa;
        let ethernet_frame =
            EthernetFrame::new(self, src_mac, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let frame_bytes = unsafe {
            slice::from_raw_parts(
                (&ethernet_frame as *const EthernetFrame<Self>) as *const u8,
                mem::size_of::<EthernetFrame<Self>>(),
            )
        };

        unsafe {
            let sock = socket(AF_PACKET, SOCK_RAW, libc::ETH_P_ALL.to_be());
            if sock < 0 {
                return Err(String::from(
                    "Failed to create socket. Did you use sudo? This program is probably not available on non-UNIX.",
                ));
            }

            let c_interface_name = CString::new(interface_name).expect("CString::new failed");

            let ifindex = if_nametoindex(c_interface_name.as_ptr());
            if ifindex == 0 {
                return Err(String::from(
                    "Failed to get interface index, make sure it's correct by using ip a or similar.",
                ));
            }

            let sockaddr = sockaddr_ll {
                sll_family: AF_PACKET as u16,
                sll_protocol: libc::ETH_P_ARP.to_be() as u16,
                sll_ifindex: ifindex as i32,
                sll_hatype: 0,
                sll_pkttype: 0,
                sll_halen: 6,
                sll_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
            };

            let result = sendto(
                sock,
                frame_bytes.as_ptr() as *const _,
                frame_bytes.len(),
                0,
                &sockaddr as *const sockaddr_ll as *const _,
                mem::size_of::<sockaddr_ll>() as u32,
            );

            if result < 0 {
                close(sock);
                return Err(String::from("Failed to send packet"));
            }

            // Receiving the ARP response
            let mut buf = [0u8; 65535];
            let n = recvfrom(
                sock,
                buf.as_mut_ptr() as *mut _,
                buf.len(),
                0,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            if n < 0 {
                close(sock);
                return Err(String::from("Failed to receive packet"));
            }

            Ok(String::from("Sent and received arp packet!"))
        }
    }
}

fn main() {
    let interface_name = "enp6s0";
    let src_mac = [0x0c, 0x9d, 0x92, 0x11, 0x0e, 0x66];
    let sender_ip = [192, 168, 2, 10];
    let target_ip = [192, 168, 2, 9];

    let arp = ArpPacket::new(1, src_mac, sender_ip, target_ip).request(interface_name.to_string());
    match arp {
        Ok(s) => println!("{}", s),
        Err(e) => eprintln!("Error: {}", e),
    }
}
