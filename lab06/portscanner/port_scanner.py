from scapy.all import *
import socket # Lưu ý: Bạn cần import thêm thư viện này để dùng gethostbyname

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389]

def scan_common_ports(target_domain, timeout=2):
    open_ports = []
    # Chuyển đổi tên miền thành địa chỉ IP
    target_ip = socket.gethostbyname(target_domain)
    
    for port in COMMON_PORTS:
        # Gửi gói tin SYN ("S") để kiểm tra cổng
        response = sr1(IP(dst=target_ip)/TCP(dport=port, flags="S"), 
                       timeout=timeout, verbose=0)
        
        # 0x12 là mã Hex của cờ SYN-ACK (Gói tin phản hồi khi cổng mở)
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            open_ports.append(port)
            # Gửi gói tin RST ("R") để đóng kết nối ngay lập tức (Stealth Scan)
            send(IP(dst=target_ip)/TCP(dport=port, flags="R"), verbose=0)
            
    return open_ports
def main():
    target_domain = input("Enter the target domain: ")

    open_ports = scan_common_ports(target_domain)

    if open_ports:
        print("Open common ports:")
        print(open_ports)
    else:
        print("No open common ports found.")

if __name__=='__main__':
    main()

