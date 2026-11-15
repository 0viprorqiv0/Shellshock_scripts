# Thu thập evidence reconnaissance trên Kali

Script `recon_evidence.sh` chỉ nhắm tới Metasploitable `172.16.1.10`. Chạy trên **Kali**, qua Gateway như mô hình lab; giữ nguyên firewall hiện tại để kết quả phản ánh đúng trạng thái đang kiểm tra. Script không chỉnh route, cài package hay sửa rule.

Copy file sang Kali rồi chạy bằng tài khoản thường:

```bash
sed -i 's/\r$//' recon_evidence.sh
bash recon_evidence.sh
```

Nếu muốn thêm các biến thể quét của mục 2.2.3 và kiểm tra Shellshock:

```bash
bash recon_evidence.sh --extended --shellshock
```

Mỗi lần chạy tạo thư mục riêng `~/recon-evidence-<UTC>-<suffix>/`. Chế độ mặc định gồm địa chỉ, route, ping, neighbor, traceroute nếu có, Nmap discovery, SYN và service/OS. Chế độ mở rộng thêm ICMP Timestamp, connect, ACK, FIN, Xmas và UDP top 10. Đây là tập lệnh cô đọng; không tái hiện mọi dòng trong tài liệu giảng dạy, không quét cả subnet hoặc toàn bộ cổng. UDP và version detection có thể tốn vài phút; kết quả bị host-timeout phải ghi là chưa hoàn tất.

`--shellshock` chạy NSE active check trên `/cgi-bin/test.cgi`, dùng hành vi marker mặc định của Nmap; không mở reverse shell. Chỉ tùy chọn này kiểm tra lỗ hổng. Các lần quét reconnaissance khác chủ yếu xác định đường đi, host và dịch vụ.

| Tệp | Dùng trong báo cáo |
| :--- | :--- |
| `00-metadata.txt` | UTC, Target, chế độ chạy, phiên bản Nmap |
| `02-route.console.txt`, `03-ping.console.txt`, `05-path.console.txt` nếu có | Đường tới Target và kết quả kết nối |
| `06-discovery.*` | Probe và phản hồi phát hiện host |
| `07-tcp.*` | Trạng thái các cổng đã chọn, gồm 80 và 4444 |
| `08-service-os.*` | Banner/version và OS fingerprint kèm cảnh báo độ tin cậy |
| `10-*` đến `15-*` nếu bật | Các kiểu quét mở rộng và kết quả thực tế |
| `20-shellshock.*` nếu bật | Kết quả NSE ở endpoint CGI |
| `status.tsv` | Mã thoát của từng bước; lỗi không làm mất các bằng chứng còn lại |
| `SHA256SUMS.txt` | Kiểm tra tệp có thay đổi sau khi thu thập |

Mỗi Nmap `-oA` lưu `.nmap`, `.xml` và `.gnmap`; tệp `.console.txt` giữ thêm lệnh, thời gian, stderr và mã thoát. Cần giữ cả thư mục, không chỉ ảnh màn hình. Hash xác nhận tính toàn vẹn từ thời điểm tạo hash, không chứng minh nguồn gốc hoặc tính chính xác của phép đo.

Sau khi chạy, xem `status.tsv`, `07-tcp.nmap`, `08-service-os.nmap` và `20-shellshock.nmap` nếu có. Không suy diễn từ exit code 0 rằng cổng mở hay Target có lỗ hổng. Ping bị chặn vẫn có thể đi cùng HTTP hoạt động; ACK/FIN/Xmas và UDP cần diễn giải đúng trạng thái Nmap trả về. Script không tự ghi kết luận thành công vào báo cáo.

Chỉ cần chụp một ảnh kết quả TCP/service chính, và một ảnh NSE nếu có kết quả đáng phân tích. Các lệnh/đầu ra khác có thể dẫn bằng tệp. Ghi đây là **lần thực nghiệm mới**, giữ riêng với các capture tháng 11 trước đó. Nếu Gateway đang DROP payload, NSE timeout hoặc không phát hiện chưa chứng minh Bash đã được vá.

Nguồn chính thức: [Nmap output / -oA](https://nmap.org/book/man-output.html), [host discovery](https://nmap.org/book/man-host-discovery.html), [http-shellshock NSE](https://nmap.org/nsedoc/scripts/http-shellshock.html).
