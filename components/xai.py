"""
Explainable AI (XAI) module for network anomaly detection system.
Contains functions for generating explanations from ML models using SHAP and Autoencoder analysis.
"""

import pandas as pd
import numpy as np
import logging
from typing import Dict, List, Optional, Any

# Set up logging
logger = logging.getLogger(__name__)
# Silence verbose XAI logs by default (can be overridden by app configs)
logger.setLevel(logging.WARNING)
logger.propagate = True

# Human-readable interpretations for technical features
HUMAN_INTERPRETATIONS = {
    "Conn State S0": "[Hành vi đáng ngờ] Kết nối được gửi đi nhưng **không nhận lại bất kỳ phản hồi nào (State: S0)**. Đây là dấu hiệu kinh điển của kỹ thuật quét mạng (Network/Port Scanning).",
    "Conn State REJ": "[Hành vi đáng ngờ] Kết nối **bị từ chối thẳng thừng (State: REJ)**. Việc này xảy ra hàng loạt thường là dấu hiệu của việc quét các port đã đóng.",
    "Conn State RSTR": "[Hành vi đáng ngờ] Kết nối được thiết lập rồi **bị chính bên gửi reset ngay lập tức (State: RSTR)**. Thường thấy trong các công cụ brute-force hoặc quét lỗi ứng dụng.",
    "Conn State RSTO": "[Hành vi đáng ngờ] Kết nối **bị đích reset (State: RSTO)**, có thể là dấu hiệu của việc từ chối kết nối hoặc phòng thủ chống tấn công.",
    "Service Binned Unknown": "[Ngữ cảnh đáng ngờ] Giao dịch đang diễn ra qua một **dịch vụ không xác định/không phổ biến**. Kẻ tấn công thường sử dụng các port/dịch vụ lạ để lẩn tránh sự phát hiện.",
    "Duration": "[Đặc điểm bất thường] **Thời gian kết nối cực ngắn**, đây là đặc điểm của các kết nối thăm dò, quét lỗi hoặc một số loại tấn công brute-force.",
    "Connection Duration": "[Đặc điểm bất thường] **Thời gian kết nối bất thường**, có thể quá ngắn (scanning) hoặc quá dài (data exfiltration).",
    "Orig Ip Bytes": "[Đặc điểm bất thường] **Lượng dữ liệu gửi đi có sự bất thường** (quá lớn hoặc quá nhỏ), có thể là dấu hiệu của việc tuồn dữ liệu hoặc gửi các gói tin thăm dò.",
    "Bytes Sent": "[Đặc điểm bất thường] **Lượng dữ liệu gửi đi bất thường**, có thể chỉ ra hoạt động data exfiltration hoặc command injection.",
    "Orig Port Binned Well-Known": "[Ngữ cảnh đáng ngờ] Kết nối xuất phát từ một **cổng trong dải 'well-known' (0-1023)**. Đây là hành vi không bình thường đối với một máy khách thông thường.",
    "Resp Ip Bytes": "[Đặc điểm bất thường] **Lượng dữ liệu phản hồi bất thường**, có thể chỉ ra việc khai thác lỗi hoặc thu thập thông tin từ hệ thống mục tiêu.",
    "Bytes Received": "[Đặc điểm bất thường] **Lượng dữ liệu nhận về bất thường**, có thể là kết quả của data harvesting hoặc malware download.",
    "Resp Port Binned": "[Ngữ cảnh đáng ngờ] **Cổng đích có đặc điểm bất thường**, có thể là dấu hiệu của việc quét port hoặc tấn công vào các dịch vụ cụ thể.",
    "Proto tcp": "[Đặc điểm bất thường] Sử dụng giao thức TCP trong ngữ cảnh bất thường, thường được sử dụng trong các cuộc tấn công có mục tiêu cụ thể.",
    "Proto udp": "[Đặc điểm bất thường] Sử dụng giao thức UDP trong ngữ cảnh bất thường, có thể liên quan đến các cuộc tấn công DDoS hoặc quét mạng nhanh.",
    "Conn State SF": "[Hành vi bình thường] Kết nối hoàn thành bình thường (State: SF), nhưng có thể có các đặc điểm khác bất thường.",
    "Service Binned": "[Ngữ cảnh đáng ngờ] Dịch vụ được phân loại có đặc điểm bất thường, cần xem xét thêm các yếu tố khác để đánh giá mức độ nguy hiểm.",
    # Enhanced network behavior features
    "Bytes Ratio": "[Hành vi đáng ngờ] **Tỷ lệ upload/download bất thường**, có thể chỉ ra data exfiltration (upload cao) hoặc malware download (download cao).",
    "Packets Ratio": "[Hành vi đáng ngờ] **Tỷ lệ gói tin gửi/nhận bất thường**, thường thấy trong port scanning (nhiều gói gửi, ít phản hồi).",
    "Avg Packet Size Orig": "[Đặc điểm bất thường] **Kích thước gói tin gửi đi bất thường**, có thể chỉ ra DNS tunneling (gói nhỏ) hoặc data exfiltration (gói lớn).",
    "Avg Packet Size Resp": "[Đặc điểm bất thường] **Kích thước gói tin phản hồi bất thường**, có thể là dấu hiệu của information gathering hoặc payload delivery.",
    "Connection Rate": "[Hành vi đáng ngờ] **Tần suất kết nối bất thường**, tần suất cao có thể chỉ ra C2 beaconing hoặc automated scanning.",
    "Failed Connection Ratio": "[Hành vi đáng ngờ] **Kết nối thất bại**, dấu hiệu rõ ràng của port scanning, brute force attacks, hoặc reconnaissance activities.",
    "Packets Sent": "[Đặc điểm bất thường] **Số lượng gói tin gửi đi bất thường**, có thể chỉ ra flooding attacks hoặc scanning activities.",
    "Packets Received": "[Đặc điểm bất thường] **Số lượng gói tin nhận về bất thường**, có thể liên quan đến data harvesting hoặc response analysis.",
    "Missed Bytes": "[Đặc điểm đáng ngờ] **Dữ liệu bị mất trong quá trình truyền**, có thể chỉ ra network evasion techniques hoặc fragmentation attacks.",
    # Enhanced categorical features
    "Duration Category": "[Mẫu hình bất thường] **Phân loại thời gian kết nối bất thường**, các kết nối quá ngắn hoặc quá dài so với dịch vụ thông thường.",
    "Traffic Pattern Upload Heavy": "[Hành vi đáng ngờ] **Mẫu traffic upload nặng**, dấu hiệu mạnh mẽ của data exfiltration hoặc command injection.",
    "Traffic Pattern Download Heavy": "[Hành vi đáng ngờ] **Mẫu traffic download nặng**, có thể chỉ ra malware download hoặc data harvesting.",
    "Traffic Pattern Balanced": "[Mẫu hình bình thường] **Mẫu traffic cân bằng**, nhưng có thể che giấu các hoạt động đáng ngờ khác.",
    "Traffic Pattern Burst": "[Hành vi đáng ngờ] **Mẫu traffic burst**, có thể chỉ ra scanning activities hoặc automated attacks.",
    "Traffic Pattern Large Transfer": "[Hành vi đáng ngờ] **Truyền tải dữ liệu lớn**, có thể là data exfiltration hoặc malware distribution.",
    "Traffic Pattern Single Packet": "[Hành vi đáng ngờ] **Giao tiếp một gói tin**, thường thấy trong reconnaissance probes hoặc heartbeat checks.",
    # NEW: C2 Beaconing specific features
    "Small Consistent Size": "[Hành vi đáng ngờ C2] **Kích thước dữ liệu nhỏ và nhất quán**, đây là đặc điểm điển hình của C2 beaconing - malware giao tiếp với command server bằng các gói tin nhỏ, đều đặn.",
    "Heartbeat Candidate": "[Hành vi đáng ngờ C2] **Kết nối heartbeat điển hình**, có đặc điểm của C2 beaconing: thời gian ngắn, dữ liệu ít, kết nối thành công - dấu hiệu của malware check-in với C2 server.",
    "Periodic Score": "[Hành vi đáng ngờ C2] **Điểm số chu kỳ cao**, chỉ ra tính đều đặn về thời gian - đặc trưng mạnh của automated C2 beaconing thay vì human browsing behavior.",
    "Beaconing Pattern High Beacon Candidate": "[Hành vi đáng ngờ C2] **Mẫu hình C2 beaconing độ tin cậy cao**, kết nối có tất cả đặc điểm của C2 communication: nhỏ, nhanh, thành công, đều đặn.",
    "Beaconing Pattern Medium Beacon Candidate": "[Hành vi đáng ngờ C2] **Mẫu hình C2 beaconing độ tin cậy trung bình**, có một số đặc điểm của C2 communication nhưng chưa rõ ràng hoàn toàn.",
    "Beaconing Pattern Quick Probe": "[Hành vi đáng ngờ C2] **Mẫu hình thăm dó nhanh**, có thể là C2 beaconing hoặc reconnaissance activity với đặc điểm kết nối rất ngắn và dữ liệu ít.",

    "Beaconing Pattern Minimal Exchange": "[Hành vi đáng ngờ C2] **Mẫu hình trao đổi tối thiểu**, đặc điểm của lightweight C2 communication hoặc heartbeat mechanism.",
    # Group Features from GroupFeatureTransformer - C2 Beaconing Detection
    "Beacon Group Count": "[Hành vi đáng ngờ C2] **Số lượng kết nối trong group beaconing**, chỉ ra mật độ communication đều đặn - đặc trưng mạnh của C2 beaconing thay vì human browsing.",
    "Beacon Group Mean Interval": "[Hành vi đáng ngờ C2] **Khoảng thời gian trung bình giữa các kết nối**, tính đều đặn cao chỉ ra automated C2 communication thay vì random human behavior.",
    "Beacon Group Cv": "[Hành vi đáng ngờ C2] **Hệ số biến thiên thời gian beaconing**, giá trị thấp chỉ ra tính nhất quán cao - đặc trưng điển hình của automated C2 heartbeat.",
    
    #  FIX: Add missing Group Features for SHAP explanations
    "beacon_group_count": "[Hành vi đáng ngờ C2] **Số lượng kết nối beaconing trong nhóm**, chỉ ra mật độ communication đều đặn - đặc trưng mạnh của C2 beaconing thay vì human browsing.",
    "beacon_group_cv": "[Hành vi đáng ngờ C2] **Hệ số biến thiên thời gian beaconing**, giá trị thấp chỉ ra tính nhất quán cao - đặc trưng điển hình của automated C2 heartbeat.",
    "beacon_channel_timediff_std": "[Hành vi đáng ngờ C2] **Độ lệch chuẩn thời gian giữa các kết nối beaconing**, chỉ ra tính đều đặn của C2 communication.",
    "beacon_channel_duration_std": "[Hành vi đáng ngờ C2] **Độ lệch chuẩn thời gian kết nối beaconing**, chỉ ra tính nhất quán của C2 sessions.",
    "beacon_channel_orig_bytes_std": "[Hành vi đáng ngờ C2] **Độ lệch chuẩn dữ liệu gửi đi trong beaconing**, chỉ ra tính đều đặn của C2 payload.",
    "horizontal_scan_unique_dst_ip_count": "[Hành vi đáng ngờ] **Số lượng IP đích khác nhau trong horizontal scanning**, chỉ ra việc quét nhiều host khác nhau từ cùng một port - dấu hiệu rõ ràng của network reconnaissance.",
    "horizontal_scan_problematic_ratio": "[Hành vi đáng ngờ] **Tỷ lệ kết nối có vấn đề trong horizontal scanning**, chỉ ra mức độ thành công của việc quét mạng - tỷ lệ cao có thể chỉ ra network mapping.",
    "vertical_scan_unique_dst_port_count": "[Hành vi đáng ngờ] **Số lượng port đích khác nhau trong vertical scanning**, chỉ ra việc quét nhiều port khác nhau từ cùng một host - dấu hiệu của service enumeration.",
    "vertical_scan_problematic_ratio": "[Hành vi đáng ngờ] **Tỷ lệ kết nối có vấn đề trong vertical scanning**, chỉ ra mức độ thành công của việc quét port - tỷ lệ cao có thể chỉ ra service discovery.",
    "ddos_group_unique_src_ip_count": "[Hành vi đáng ngờ DDoS] **Số lượng IP nguồn khác nhau trong nhóm DDoS**, chỉ ra mức độ phân tán của cuộc tấn công - số lượng cao có thể chỉ ra botnet hoặc coordinated attack.",
    
    # Missing mappings for important SHAP features
    "Is Auth Port": "[Ngữ cảnh đáng ngờ] **Cổng đích có đặc điểm authentication**, có thể là dấu hiệu của việc tấn công vào các dịch vụ xác thực.",
    "Hist R Count": "[Hành vi đáng ngờ] **Số lượng gói tin bị reset trong lịch sử kết nối**, có thể chỉ ra scanning behavior hoặc connection probing.",
    "Is Auth Service": "[Tấn công Xác thực] Hành vi nhắm vào một dịch vụ xác thực (SSH, FTP...), một mục tiêu phổ biến của tấn công brute-force.",
    "Failed Connection Ratio": "[Hành vi đáng ngờ] **Kết nối thất bại**, dấu hiệu rõ ràng của port scanning, brute force attacks, hoặc reconnaissance activities.",
    
    # DNS Log Features - Bổ sung thêm
    "Query Length": "[Độ dài query DNS] **Query DNS quá dài** có thể chỉ ra DNS tunneling, data exfiltration qua DNS, hoặc malicious payload encoding.",
    "Query Entropy": "[Entropy của query DNS] **Entropy cao trong query DNS** có thể chỉ ra encoded data, DNS tunneling, hoặc obfuscated communication.",
    "Subdomain Count": "[Số lượng subdomain] **Số subdomain bất thường** có thể chỉ ra DNS tunneling, data encoding, hoặc malicious domain generation.",
    "Numeric Ratio": "[Tỷ lệ ký tự số] **Tỷ lệ số trong query DNS cao** có thể chỉ ra encoded data, DNS tunneling, hoặc binary data encoding.",
    "Ngram Score": "[Điểm n-gram] **Điểm n-gram bất thường** có thể chỉ ra encoded data, obfuscated communication, hoặc malicious payload.",
    "Has Base64 Pattern": "[Có pattern Base64] **Query DNS chứa Base64** có thể chỉ ra data encoding, DNS tunneling, hoặc malicious payload transmission.",
    "Has Hex Pattern": "[Có pattern Hex] **Query DNS chứa Hex** có thể chỉ ra encoded data, DNS tunneling, hoặc binary data transmission.",
    "Has Long Subdomain": "[Có subdomain dài] **Subdomain quá dài** có thể chỉ ra DNS tunneling, data encoding, hoặc malicious domain generation.",
    "Suspicious Length": "[Độ dài đáng ngờ] **Query DNS có độ dài đáng ngờ** có thể chỉ ra DNS tunneling, data exfiltration, hoặc malicious communication.",
    "Char Diversity": "[Đa dạng ký tự] **Đa dạng ký tự bất thường** có thể chỉ ra encoded data, DNS tunneling, hoặc obfuscated communication.",
    "Vowel Consonant Ratio": "[Tỷ lệ nguyên âm phụ âm] **Tỷ lệ nguyên âm/phụ âm bất thường** có thể chỉ ra encoded data, DNS tunneling, hoặc non-human generated queries.",
    "Compressed Pattern": "[Pattern nén] **Query DNS có pattern nén** có thể chỉ ra compressed data, DNS tunneling, hoặc obfuscated communication.",
    "Unusual TLD": "[TLD bất thường] **Top-level domain bất thường** có thể chỉ ra malicious domain, DNS tunneling, hoặc command & control communication.",
    "Avg TTL": "[TTL trung bình] **TTL bất thường** có thể chỉ ra DNS tunneling, malicious DNS, hoặc command & control infrastructure.",
    "Min TTL": "[TTL tối thiểu] **TTL tối thiểu bất thường** có thể chỉ ra DNS tunneling, fast-flux DNS, hoặc malicious infrastructure.",
    "Is Qtype TXT": "[Query type TXT] **Query TXT bất thường** có thể chỉ ra DNS tunneling, data exfiltration, hoặc command & control communication.",
    "Is Qtype NULL": "[Query type NULL] **Query NULL bất thường** có thể chỉ ra DNS tunneling, data exfiltration, hoặc malicious DNS usage.",
    "Is NXDOMAIN": "[Response NXDOMAIN] **Response NXDOMAIN bất thường** có thể chỉ ra DNS tunneling, malicious domain queries, hoặc reconnaissance."
}

# Human-readable interpretations for Autoencoder features
# These explain why the model had difficulty reconstructing certain features
HUMAN_INTERPRETATIONS_AE = {
    "History Length": "[Mẫu hình bất thường] Chuỗi sự kiện của kết nối (connection history) có **độ dài hoặc cấu trúc rất lạ**, không giống với các kết nối bình thường mà model đã học.",
    "Timeout Flag": "[Hành vi đáng ngờ] Kết nối này có **dấu hiệu bị timeout (hết thời gian chờ)**, một đặc điểm không thường thấy trong các giao dịch thành công và có thể chỉ ra lỗi mạng hoặc hành vi thăm dò.",
    "Service Binned Other": "[Ngữ cảnh đáng ngờ] Giao dịch đang sử dụng một **dịch vụ không phổ biến hoặc đã bị che giấu**, khiến model khó có thể tái tạo lại một cách chính xác.",
    "Service Binned Unknown": "[Ngữ cảnh đáng ngờ] Giao dịch đang sử dụng một **dịch vụ không xác định**, khiến model khó có thể tái tạo lại một cách chính xác.",
    "Duration": "[Đặc điểm bất thường] **Thời gian kết nối quá dài hoặc quá ngắn** so với các kết nối thông thường cho cùng loại dịch vụ.",
    "Connection Duration": "[Đặc điểm bất thường] **Thời gian kết nối bất thường**, model không thể tái tạo chính xác do khác biệt so với các mẫu học được.",
    "Orig Ip Bytes": "[Đặc điểm bất thường] **Lượng dữ liệu gửi đi không nhất quán** với các mẫu traffic thông thường, có thể là dấu hiệu của việc tuồn dữ liệu hoặc các gói tin C&C.",
    "Bytes Sent": "[Đặc điểm bất thường] **Lượng dữ liệu gửi đi khác thường**, model khó tái tạo do không phù hợp với các mẫu benign đã học.",
    "Resp Ip Bytes": "[Đặc điểm bất thường] **Lượng dữ liệu nhận về có sự sai khác lớn**, có thể là kết quả của một lệnh tấn công hoặc một phản hồi lỗi từ server.",
    "Bytes Received": "[Đặc điểm bất thường] **Lượng dữ liệu nhận về bất thường**, model không thể tái tạo chính xác do khác biệt với traffic patterns thông thường.",
    "Conn State": "[Trạng thái bất thường] **Trạng thái kết thúc của kết nối** (ví dụ: S0, REJ) là một yếu tố bất thường mạnh mẽ mà model không mong đợi.",
    "Orig Port Binned": "[Ngữ cảnh đáng ngờ] **Cổng nguồn có đặc điểm bất thường**, không phù hợp với các mẫu kết nối thông thường mà model đã học.",
    "Resp Port Binned": "[Ngữ cảnh đáng ngờ] **Cổng đích có đặc điểm bất thường**, có thể là dấu hiệu của việc quét port hoặc tấn công vào các dịch vụ cụ thể.",
    "Proto": "[Đặc điểm bất thường] **Giao thức mạng được sử dụng** trong ngữ cảnh bất thường, không phù hợp với các mẫu traffic thông thường.",
    "Service": "[Ngữ cảnh đáng ngờ] **Dịch vụ mạng** có đặc điểm không thường thấy, khiến model khó tái tạo chính xác.",
    "Local Orig": "[Đặc điểm bất thường] **Đặc tính địa phương của nguồn kết nối** có sự khác biệt so với các mẫu thông thường.",
    "Local Resp": "[Đặc điểm bất thường] **Đặc tính địa phương của đích kết nối** có sự khác biệt so với các mẫu thông thường.",
    # Enhanced network behavior features for AE
    "Bytes Ratio": "[Mẫu hình bất thường] **Tỷ lệ upload/download** có sự khác biệt lớn so với các kết nối bình thường, model khó tái tạo chính xác.",
    "Packets Ratio": "[Mẫu hình bất thường] **Tỷ lệ gói tin gửi/nhận** không phù hợp với các mẫu traffic thông thường mà model đã học.",
    "Avg Packet Size Orig": "[Đặc điểm bất thường] **Kích thước gói tin gửi đi** có sự khác biệt đáng kể so với các kết nối benign, khiến model khó reconstruction.",
    "Avg Packet Size Resp": "[Đặc điểm bất thường] **Kích thước gói tin phản hồi** không nhất quán với các mẫu học được, chỉ ra hành vi bất thường.",
    "Connection Rate": "[Mẫu hình bất thường] **Tần suất kết nối** khác biệt so với các mẫu thông thường, có thể chỉ ra automated behavior.",
    "Failed Connection Ratio": "[Hành vi bất thường] **Tỷ lệ kết nối thất bại** là một đặc điểm mạnh mẽ không thường thấy trong traffic bình thường.",
    "Packets Sent": "[Đặc điểm bất thường] **Số lượng gói tin gửi đi** khác biệt đáng kể so với các mẫu benign mà model đã học.",
    "Packets Received": "[Đặc điểm bất thường] **Số lượng gói tin nhận về** không phù hợp với các pattern thông thường, khiến model khó tái tạo.",
    "Missed Bytes": "[Đặc điểm đáng ngờ] **Dữ liệu bị mất** là một anomaly mạnh mẽ không thường xuất hiện trong traffic bình thường.",
    # Enhanced categorical features for AE
    "Duration Category": "[Mẫu hình bất thường] **Phân loại thời gian kết nối** không phù hợp với các mẫu đã học, chỉ ra hành vi bất thường.",
    "Traffic Pattern Upload Heavy": "[Mẫu hình bất thường] **Mẫu traffic upload nặng** là đặc điểm không thường thấy trong benign traffic.",
    "Traffic Pattern Download Heavy": "[Mẫu hình bất thường] **Mẫu traffic download nặng** khác biệt so với các mẫu thông thường mà model đã học.",
    "Traffic Pattern Balanced": "[Mẫu hình đặc biệt] **Mẫu traffic cân bằng** nhưng có các đặc điểm khác khiến model khó tái tạo chính xác.",
    "Traffic Pattern Burst": "[Mẫu hình bất thường] **Mẫu traffic burst** là đặc điểm không phổ biến trong các kết nối bình thường.",
    "Traffic Pattern Large Transfer": "[Mẫu hình bất thường] **Mẫu truyền tải dữ liệu lớn** khác biệt đáng kể so với traffic patterns thông thường.",
    "Traffic Pattern Single Packet": "[Mẫu hình bất thường] **Mẫu giao tiếp một gói tin** là đặc điểm không thường thấy trong các kết nối application-layer bình thường.",
    # NEW: C2 Beaconing specific features for AE
    "Small Consistent Size": "[Mẫu hình bất thường C2] **Kích thước dữ liệu nhỏ và nhất quán** là đặc điểm không phổ biến trong benign traffic, model khó tái tạo do tính đặc trưng của C2 beaconing.",
    "Heartbeat Candidate": "[Mẫu hình bất thường C2] **Pattern heartbeat điển hình** không thường thấy trong traffic bình thường, chỉ ra khả năng cao là automated C2 communication.",
    "Periodic Score": "[Mẫu hình bất thường C2] **Tính chu kỳ cao** là đặc điểm mạnh mẽ của automated behavior, khác biệt hoàn toàn so với human browsing patterns mà model đã học.",
    "Beaconing Pattern High Beacon Candidate": "[Mẫu hình bất thường C2] **Combination pattern có độ tin cậy cao** cho C2 beaconing, model không thể tái tạo do chưa từng học được pattern này trong benign data.",
    "Beaconing Pattern Medium Beacon Candidate": "[Mẫu hình bất thường C2] **Pattern có đặc điểm C2 trung bình**, model gặp khó khăn trong reconstruction do sự khác biệt với normal traffic patterns.",
    "Beaconing Pattern Quick Probe": "[Mẫu hình bất thường C2] **Pattern thăm dò nhanh**, đặc điểm không thường thấy trong benign traffic, khiến model khó tái tạo chính xác.",
    "Beaconing Pattern Minimal Exchange": "[Mẫu hình bất thường C2] **Pattern trao đổi tối thiểu**, là đặc trưng của lightweight malware communication, khác biệt so với legitimate application traffic.",
    # Group Features from GroupFeatureTransformer - C2 Beaconing Detection
    "Beacon Group Count": "[Hành vi đáng ngờ C2] **Số lượng kết nối trong group beaconing**, chỉ ra mật độ communication đều đặn - đặc trưng mạnh của C2 beaconing thay vì human browsing.",
    "Beacon Group Mean Interval": "[Hành vi đáng ngờ C2] **Khoảng thời gian trung bình giữa các kết nối**, tính đều đặn cao chỉ ra automated C2 communication thay vì random human behavior.",
    "Beacon Group Std Interval": "[Hành vi đáng ngờ C2] **Độ lệch chuẩn thời gian giữa kết nối**, độ lệch thấp chỉ ra tính chu kỳ đều đặn của malware beaconing.",
    "Beacon Group Cv": "[Hành vi đáng ngờ C2] **Hệ số biến thiên thời gian beaconing**, giá trị thấp chỉ ra tính nhất quán cao - đặc trưng điển hình của automated C2 heartbeat.",
    # Group Features - Scanning Detection  
    "Scan Group Unique Dst Port Count": "[Hành vi đáng ngờ Scanning] **Số port đích unique trong group scanning**, số lượng lớn chỉ ra port scanning hoặc service discovery attacks.",
    "Scan Group Rej Ratio": "[Hành vi đáng ngờ Scanning] **Tỷ lệ kết nối bị reject trong group**, tỷ lệ cao chỉ ra reconnaissance scanning hoặc brute force attempts.",
    # Group Features - DDoS Detection
    "Ddos Group Unique Src Ip Count": "[Hành vi đáng ngờ DDoS] **Số IP nguồn unique trong group**, số lượng lớn có thể chỉ ra distributed attack hoặc botnet activity.",
    "Ddos Group Total Bytes": "[Hành vi đáng ngờ DDoS] **Tổng bytes trong group DDoS**, lưu lượng lớn có thể chỉ ra volumetric attack hoặc data exfiltration.",
    
    # Missing mappings for important features
    "Is Auth Port": "[Tấn công Xác thực] Kết nối đến một cổng xác thực chuẩn (21, 22, 23), tăng mức độ nghi ngờ khi có lỗi.",
    "Hist R Count": "[Hành vi đáng ngờ] **Số lượng gói tin bị reset trong lịch sử kết nối**, có thể chỉ ra scanning behavior hoặc connection probing.",
    "Is Auth Service": "[Tấn công Xác thực] Hành vi nhắm vào một dịch vụ xác thực (SSH, FTP...), một mục tiêu phổ biến của tấn công brute-force.",
    "Failed Connection Ratio": "[Hành vi bất thường] **Tỷ lệ kết nối thất bại** là một đặc điểm mạnh mẽ không thường thấy trong traffic bình thường.",
    
    # DNS Log Features - Bổ sung thêm cho Autoencoder
    "Query Length": "[Reconstruction Error - Query Length] **Model gặp khó khăn tái tạo độ dài query DNS** do giá trị bất thường - có thể chỉ ra DNS tunneling, data exfiltration, hoặc malicious payload.",
    "Query Entropy": "[Reconstruction Error - Query Entropy] **Model gặp khó khăn tái tạo entropy query DNS** do giá trị bất thường - có thể chỉ ra encoded data, DNS tunneling, hoặc obfuscated communication.",
    "Subdomain Count": "[Reconstruction Error - Subdomain Count] **Model gặp khó khăn tái tạo số subdomain** do giá trị bất thường - có thể chỉ ra DNS tunneling, data encoding, hoặc malicious domain generation.",
    "Numeric Ratio": "[Reconstruction Error - Numeric Ratio] **Model gặp khó khăn tái tạo tỷ lệ số trong query DNS** do giá trị bất thường - có thể chỉ ra encoded data, DNS tunneling, hoặc binary data encoding.",
    "Ngram Score": "[Reconstruction Error - Ngram Score] **Model gặp khó khăn tái tạo điểm n-gram** do giá trị bất thường - có thể chỉ ra encoded data, obfuscated communication, hoặc malicious payload.",
    "Has Base64 Pattern": "[Reconstruction Error - Has Base64 Pattern] **Model gặp khó khăn tái tạo pattern Base64** do tính chất bất thường - có thể chỉ ra data encoding, DNS tunneling, hoặc malicious payload.",
    "Has Hex Pattern": "[Reconstruction Error - Has Hex Pattern] **Model gặp khó khăn tái tạo pattern Hex** do tính chất bất thường - có thể chỉ ra encoded data, DNS tunneling, hoặc binary data transmission.",
    "Has Long Subdomain": "[Reconstruction Error - Has Long Subdomain] **Model gặp khó khăn tái tạo subdomain dài** do tính chất bất thường - có thể chỉ ra DNS tunneling, data encoding, hoặc malicious domain generation.",
    "Suspicious Length": "[Reconstruction Error - Suspicious Length] **Model gặp khó khăn tái tạo độ dài đáng ngờ** do tính chất bất thường - có thể chỉ ra DNS tunneling, data exfiltration, hoặc malicious communication.",
    "Char Diversity": "[Reconstruction Error - Char Diversity] **Model gặp khó khăn tái tạo đa dạng ký tự** do tính chất bất thường - có thể chỉ ra encoded data, DNS tunneling, hoặc obfuscated communication.",
    "Vowel Consonant Ratio": "[Reconstruction Error - Vowel Consonant Ratio] **Model gặp khó khăn tái tạo tỷ lệ nguyên âm/phụ âm** do tính chất bất thường - có thể chỉ ra encoded data, DNS tunneling, hoặc non-human generated queries.",
    "Compressed Pattern": "[Reconstruction Error - Compressed Pattern] **Model gặp khó khăn tái tạo pattern nén** do tính chất bất thường - có thể chỉ ra compressed data, DNS tunneling, hoặc obfuscated communication.",
    "Unusual TLD": "[Reconstruction Error - Unusual TLD] **Model gặp khó khăn tái tạo TLD bất thường** do tính chất bất thường - có thể chỉ ra malicious domain, DNS tunneling, hoặc command & control communication.",
    "Avg TTL": "[Reconstruction Error - Avg TTL] **Model gặp khó khăn tái tạo TTL trung bình** do giá trị bất thường - có thể chỉ ra DNS tunneling, malicious DNS, hoặc command & control infrastructure.",
    "Min TTL": "[Reconstruction Error - Min TTL] **Model gặp khó khăn tái tạo TTL tối thiểu** do giá trị bất thường - có thể chỉ ra DNS tunneling, fast-flux DNS, hoặc malicious infrastructure.",
    "Is Qtype TXT": "[Reconstruction Error - Is Qtype TXT] **Model gặp khó khăn tái tạo query TXT** do tính chất bất thường - có thể chỉ ra DNS tunneling, data exfiltration, hoặc command & control communication.",
    "Is Qtype NULL": "[Reconstruction Error - Is Qtype NULL] **Model gặp khó khăn tái tạo query NULL** do tính chất bất thường - có thể chỉ ra DNS tunneling, data exfiltration, hoặc malicious DNS usage.",
    "Is NXDOMAIN": "[Reconstruction Error - Is NXDOMAIN] **Model gặp khó khăn tái tạo response NXDOMAIN** do tính chất bất thường - có thể chỉ ra DNS tunneling, malicious domain queries, hoặc reconnaissance."
}

def translate_shap_to_human_readable(shap_explanation_list: list, connection_details: dict = None, log_type: str = 'conn') -> list:
    """
    Translate SHAP explanations to human-readable format for both conn.log and dns.log.
    
    Args:
        shap_explanation_list: List of SHAP explanations
        connection_details: Connection or DNS details
        log_type: 'conn' for connection logs, 'dns' for DNS logs
        
    Returns:
        List of human-readable explanations
    """
    try:
        human_readable = []
        
        for explanation in shap_explanation_list:
            feature = explanation.get('feature', 'Unknown')
            value = explanation.get('value', 0)
            direction = explanation.get('direction', 'normal')
            
            # ⚡ OPTIMIZED: Create better human-readable explanation based on log type
            if log_type == 'dns':
                if direction == 'tunneling':
                    if value < -0.1:  # Strong negative SHAP value
                        human_explanation = f"🚨 **CẢNH BÁO CAO**: Phát hiện mạnh mẽ DNS tunneling qua đặc trưng '{feature}'. Đây có thể là dấu hiệu của việc tuồn dữ liệu bất hợp pháp hoặc command & control communication."
                    else:
                        human_explanation = f"⚠️ **CẢNH BÁO TRUNG BÌNH**: Phát hiện vừa phải DNS tunneling qua đặc trưng '{feature}'. Cần theo dõi thêm để xác định mức độ nguy hiểm."
                else:
                    if value > 0.1:  # Strong positive SHAP value
                        human_explanation = f" **BÌNH THƯỜNG**: Đặc trưng '{feature}' cho thấy traffic DNS hoạt động bình thường, không có dấu hiệu bất thường."
                    else:
                        human_explanation = f"ℹ️ **BÌNH THƯỜNG**: Đặc trưng '{feature}' cho thấy traffic DNS hoạt động bình thường."
            else:  # conn.log
                if direction == 'anomaly':
                    if value < -0.1:  # Strong negative SHAP value
                        human_explanation = f"🚨 **CẢNH BÁO CAO**: Phát hiện mạnh mẽ network anomaly qua đặc trưng '{feature}'. Đây có thể là dấu hiệu của port scanning, DDoS attack, hoặc C2 beaconing."
                    else:
                        human_explanation = f"⚠️ **CẢNH BÁO TRUNG BÌNH**: Phát hiện vừa phải network anomaly qua đặc trưng '{feature}'. Cần theo dõi thêm để xác định mức độ nguy hiểm."
                else:
                    if value > 0.1:  # Strong positive SHAP value
                        human_explanation = f" **BÌNH THƯỜNG**: Đặc trưng '{feature}' cho thấy network traffic hoạt động bình thường, không có dấu hiệu bất thường."
                    else:
                        human_explanation = f"ℹ️ **BÌNH THƯỜNG**: Đặc trưng '{feature}' cho thấy network traffic hoạt động bình thường."
            
            human_readable.append({
                "feature": feature,
                "explanation": human_explanation,
                "impact": abs(value),
                "direction": direction,
                "log_type": log_type
            })
        
        return human_readable
        
    except Exception as e:
        logger.warning(f"Error translating SHAP to human readable for {log_type}: {str(e)}")
        return []

def translate_ae_to_human_readable(ae_explanation_list: list) -> list:
    """
    Translates a technical Autoencoder explanation list into human-readable security insights.
    
    Args:
        ae_explanation_list: List of Autoencoder explanation dictionaries with 'feature' and 'contribution_percent' keys
        
    Returns:
        List of human-readable security narratives explaining why the model had difficulty reconstructing features
    """
    if not ae_explanation_list:
        return []
    
    # Process autoencoder explanation for human-readable narratives
    
    narratives = []
    for item in ae_explanation_list:
        feature_name = item.get('feature', '')
        
        # The feature_name from AE explanation is already cleaned by format_ae_explanation
        # So we try direct matching first, then fallback to cleaning if needed
        logger.info(f"AE Processing feature: {feature_name}")
        
        # Find the best matching key in the Autoencoder interpretation dictionary
        matched_key = None
        
        # ⚡ OPTIMIZED: Try exact match first with the already-cleaned feature name
        if feature_name in HUMAN_INTERPRETATIONS_AE:
            matched_key = feature_name
            logger.info(f"AE EXACT MATCH: {feature_name} -> {matched_key}")
        else:
            # ⚡ OPTIMIZED: Try partial matching with the feature name as-is
            for key in HUMAN_INTERPRETATIONS_AE:
                if (key.lower() in feature_name.lower() or 
                    feature_name.lower() in key.lower()):
                    matched_key = key
                    logger.info(f"AE PARTIAL MATCH: {feature_name} -> {key}")
                    break
            
            # ⚡ OPTIMIZED: If still no match, try cleaning the feature name (fallback)
            if not matched_key:
                clean_feature = clean_feature_name(feature_name)
                logger.info(f"AE Trying cleaned version: {feature_name} -> {clean_feature}")
                
                if clean_feature in HUMAN_INTERPRETATIONS_AE:
                    matched_key = clean_feature
                    logger.info(f"AE CLEANED MATCH: {feature_name} -> {clean_feature} -> {matched_key}")
                else:
                    for key in HUMAN_INTERPRETATIONS_AE:
                        if (key.lower() in clean_feature.lower() or 
                            clean_feature.lower() in key.lower()):
                            matched_key = key
                            logger.info(f"AE CLEANED PARTIAL MATCH: {feature_name} -> {clean_feature} -> {key}")
                            break
        
        if matched_key:
            narratives.append(HUMAN_INTERPRETATIONS_AE[matched_key])
            logger.info(f"AE XAI: ✓ Added interpretation for '{feature_name}' -> '{matched_key}'")
        else:
            logger.info(f"AE XAI: ✗ No interpretation found for feature '{feature_name}'")
    
    # Return unique narratives to avoid duplicates
    unique_narratives = list(dict.fromkeys(narratives))
    logger.info(f"AE XAI: Final result - {len(unique_narratives)} unique explanations from {len(ae_explanation_list)} features")
    logger.info(f"🔍 AE XAI OUTPUT: {unique_narratives}")
    
    return unique_narratives

def get_autoencoder_explanation(X_original: np.ndarray, X_reconstructed: np.ndarray, 
                               feature_names: Optional[List[str]] = None, top_n: int = 5) -> List[Dict[str, Any]]:
    """
    Generate native explainability for Autoencoder based on per-feature reconstruction error.
    
    Args:
        X_original: Original preprocessed data (1D array)
        X_reconstructed: Reconstructed data from autoencoder (1D array)
        feature_names: Names of the features (optional)
        top_n: Number of top contributing features to return
        
    Returns:
        List of dictionaries with feature names and reconstruction errors
    """
    try:
        if feature_names is None or len(feature_names) != len(X_original):
            # Fallback feature names if not available
            feature_names = [f"feature_{i}" for i in range(len(X_original))]
        
        # Calculate squared error for each feature
        feature_errors = np.power(X_original - X_reconstructed, 2).flatten()
        
        # Create DataFrame for easy sorting
        error_df = pd.DataFrame({
            'feature': feature_names,
            'error': feature_errors,
            'original_value': X_original.flatten(),
            'reconstructed_value': X_reconstructed.flatten(),
            'difference': np.abs(X_original - X_reconstructed).flatten()
        })
        
        # Sort by error in descending order
        error_df = error_df.sort_values('error', ascending=False)
        
        # Get top N features
        top_features = error_df.head(top_n)
        
        # Convert to list of dictionaries for easy use in UI
        explanation_list = []
        for _, row in top_features.iterrows():
            explanation_list.append({
                'feature': clean_feature_name(row['feature']),
                'error': row['error'],
                'original_value': row['original_value'],
                'reconstructed_value': row['reconstructed_value'],
                'difference': row['difference'],
                'contribution_percent': (row['error'] / feature_errors.sum()) * 100 if feature_errors.sum() > 0 else 0
            })
        
        return explanation_list
        
    except Exception as e:
        logger.warning(f"Error generating Autoencoder explanation: {str(e)}")
        return []

def get_shap_explanation(shap_values: np.ndarray, feature_names: Optional[List[str]] = None, 
                        top_n: int = 5) -> Dict[str, Any]:
    """
    Generate human-readable SHAP explanation for anomaly detection.
    
    Args:
        shap_values: SHAP values for the prediction
        feature_names: Names of the features
        top_n: Number of top contributing features to return
        
    Returns:
        Dictionary with explanation data
    """
    try:
        if shap_values is None:
            return {'error': 'SHAP values not available'}
        
        if feature_names is None:
            # Fallback feature names if not available
            feature_names = [f"feature_{i}" for i in range(len(shap_values))]
        
        # Ensure we have the right number of feature names
        n_features = len(shap_values)
        if len(feature_names) < n_features:
            # Pad with generic names if needed
            feature_names = feature_names + [f'feature_{i}' for i in range(len(feature_names), n_features)]
        else:
            feature_names = feature_names[:n_features]
        
        # Create DataFrame with features and their SHAP values
        explanation_df = pd.DataFrame({
            'feature': feature_names,
            'shap_value': shap_values,
            'abs_shap_value': np.abs(shap_values)
        })
        
        # Sort by absolute SHAP value (importance)
        explanation_df = explanation_df.sort_values('abs_shap_value', ascending=False)
        
        # Get top contributing features
        top_features = explanation_df.head(top_n)
        
        # Calculate total influence
        total_influence = np.sum(np.abs(shap_values))
        
        explanation = {
            'top_features': top_features.to_dict('records'),
            'total_influence': total_influence,
            'explanation_summary': generate_explanation_text(top_features)
        }
        
        return explanation
        
    except Exception as e:
        return {'error': f'Error generating explanation: {str(e)}'}

def format_shap_explanation(shap_values: np.ndarray, feature_names: Optional[List[str]] = None, 
                           top_n: int = 5, log_type: str = 'conn') -> Dict[str, Any]:
    """
    Format SHAP values into standardized explanation format for both conn.log and dns.log.
    
    Args:
        shap_values: SHAP values array
        feature_names: List of feature names
        top_n: Number of top features to return
        log_type: 'conn' for connection logs, 'dns' for DNS logs
        
    Returns:
        Dict with structured SHAP explanation including top_features, summary, and total_influence
    """
    try:
        # Process SHAP values for explanation
        
        if feature_names is None or len(feature_names) < len(shap_values):
            # Fallback feature names
            logger.warning(f"🚨 SHAP falling back to generic names! feature_names={len(feature_names) if feature_names else 0}, shap_values={len(shap_values)}")
            feature_names = [f"{log_type.upper()}_Feature {i}" for i in range(len(shap_values))]
        else:
            feature_names = feature_names[:len(shap_values)]
            logger.debug(f"Using meaningful feature names for {log_type} SHAP explanation")
        
        # Create explanation list
        explanations = []
        feature_importance = list(zip(feature_names, shap_values, np.abs(shap_values)))
        
        # Sort by absolute importance
        feature_importance.sort(key=lambda x: x[2], reverse=True)
        
        for feature_name, shap_value, abs_value in feature_importance[:top_n]:
            # Use appropriate direction based on log type
            if log_type == 'dns':
                direction = "tunneling" if shap_value < 0 else "normal"
            else:  # conn.log
                direction = "anomaly" if shap_value < 0 else "normal"
            
            explanations.append({
                "feature": clean_feature_name(feature_name),
                "shap_value": float(shap_value),
                "importance": float(abs_value),
                "direction": direction,
                "log_type": log_type  # Add log type for identification
            })
        
        # Calculate total influence
        total_influence = np.sum(np.abs(shap_values))
        
        # Generate summary text
        summary = generate_shap_summary(explanations, log_type)
        
        # Return structured dict format that dashboard expects
        return {
            'top_features': explanations,
            'total_influence': float(total_influence),
            'summary': summary,
            'log_type': log_type,
            'feature_count': len(explanations)
        }
        
    except Exception as e:
        logger.warning(f"Error formatting SHAP explanation for {log_type}: {str(e)}")
        return {
            'top_features': [],
            'total_influence': 0.0,
            'summary': f"Error: {str(e)}",
            'log_type': log_type,
            'feature_count': 0
        }

def format_ae_explanation(X_original: np.ndarray, X_reconstructed: np.ndarray, 
                         feature_names: Optional[List[str]] = None, top_n: int = 5) -> List[Dict[str, Any]]:
    """
    Format Autoencoder explanation into standardized format.
    
    Args:
        X_original: Original preprocessed data
        X_reconstructed: Reconstructed data from autoencoder
        feature_names: List of feature names
        top_n: Number of top features to return
        
    Returns:
        List of feature explanations in standard format
    """
    try:
        # Process autoencoder data for explanation
        
        # ⚡ DEBUG: Log feature_names trước khi xử lý
        logger.info(f"🔍 AE FORMAT DEBUG: Received feature_names count={len(feature_names) if feature_names else 0}")
        logger.info(f"🔍 AE FORMAT DEBUG: X_original shape={X_original.shape}, size={X_original.size}")
        
        if feature_names is None or len(feature_names) < X_original.size:
            logger.warning(f"🚨 AE falling back to generic names! feature_names={len(feature_names) if feature_names else 0}, X_original size={X_original.size}")
            feature_names = [f"Feature {i}" for i in range(X_original.size)]
        else:
            feature_names = feature_names[:X_original.size]
            logger.debug(f"Using meaningful feature names for AE explanation")
        
        # Calculate per-feature reconstruction errors
        feature_errors = np.power(X_original - X_reconstructed, 2).flatten()
        
        # ⚡ DEBUG: Log feature counts để đảm bảo 5 features
        logger.info(f"🔍 AE FORMAT DEBUG: X_original shape={X_original.shape}, X_reconstructed shape={X_reconstructed.shape}")
        logger.info(f"🔍 AE FORMAT DEBUG: feature_errors count={len(feature_errors)}, feature_names count={len(feature_names)}")
        logger.info(f"🔍 AE FORMAT DEBUG: top_n={top_n}, will return {min(top_n, len(feature_errors))} features")
        
        # Create explanation list
        explanations = []
        feature_data = list(zip(feature_names, feature_errors, X_original.flatten(), X_reconstructed.flatten()))
        
        # Sort by error (descending)
        feature_data.sort(key=lambda x: x[1], reverse=True)
        
        total_error = np.sum(feature_errors)
        
        for feature_name, error, orig_val, recon_val in feature_data[:top_n]:
            explanations.append({
                "feature": clean_feature_name(feature_name),
                "error": float(error),
                "original_value": float(orig_val),
                "reconstructed_value": float(recon_val),
                "difference": float(abs(orig_val - recon_val)),
                "contribution_percent": float((error / total_error) * 100) if total_error > 0 else 0.0
            })
        
        return explanations
        
    except Exception as e:
        logger.warning(f"Error formatting Autoencoder explanation: {str(e)}")
        return []

def generate_explanation_text(top_features: pd.DataFrame) -> str:
    """Generate human-readable explanation text."""
    try:
        explanations = []
        
        for _, row in top_features.iterrows():
            feature = row['feature']
            shap_value = row['shap_value']
            
            # Determine if feature pushes toward anomaly or normal
            direction = "🔴 toward ANOMALY" if shap_value < 0 else "🟢 toward NORMAL"  # Correct logic for IsolationForest
            
            # Clean up feature names for display
            clean_feature = clean_feature_name(feature)
            
            explanation = f"**{clean_feature}**: {direction} (impact: {abs(shap_value):.3f})"
            explanations.append(explanation)
        
        return "\n\n".join(explanations)
        
    except Exception:
        return "Could not generate explanation text"

def generate_shap_summary(explanations: List[Dict[str, Any]], log_type: str = 'conn') -> str:
    """Generate human-readable summary of SHAP explanations."""
    try:
        if not explanations:
            return "No significant features identified"
        
        # Count anomaly vs normal indicators
        anomaly_count = sum(1 for exp in explanations if exp.get('direction') == 'anomaly')
        normal_count = len(explanations) - anomaly_count
        
        # Get top feature
        top_feature = explanations[0] if explanations else {}
        top_feature_name = top_feature.get('feature', 'Unknown')
        top_importance = top_feature.get('importance', 0.0)
        
        if log_type == 'dns':
            summary = f"DNS query analysis shows {len(explanations)} significant features. "
            if anomaly_count > normal_count:
                summary += f"Top indicator: {top_feature_name} (tunneling score: {top_importance:.3f})"
            else:
                summary += f"Top indicator: {top_feature_name} (normal score: {top_importance:.3f})"
        else:  # conn.log
            summary = f"Connection analysis shows {len(explanations)} significant features. "
            if anomaly_count > normal_count:
                summary += f"Top anomaly indicator: {top_feature_name} (impact: {top_importance:.3f})"
            else:
                summary += f"Top normal indicator: {top_feature_name} (impact: {top_importance:.3f})"
        
        return summary
        
    except Exception as e:
        logger.warning(f"Error generating SHAP summary: {str(e)}")
        return "Summary generation failed"

def clean_feature_name(feature_name: str) -> str:
    """Clean up feature names for better readability with enhanced features support."""
    # Enhanced mapping for all features including new enhanced ones
    name_mapping = {
        # Original features
        'duration': 'Connection Duration',
        'orig_bytes': 'Bytes Sent',
        'resp_bytes': 'Bytes Received',
        'orig_pkts': 'Packets Sent',
        'resp_pkts': 'Packets Received',
        'orig_ip_bytes': 'Orig Ip Bytes',
        'resp_ip_bytes': 'Resp Ip Bytes',
        'hist_len': 'History Length',
        'hist_R_count': 'Reset Flags',
        'hist_has_T': 'Timeout Flag',
        'missed_bytes': 'Missed Bytes',
        # Enhanced network behavior features
        'bytes_ratio': 'Bytes Ratio',
        'packets_ratio': 'Packets Ratio',
        'avg_packet_size_orig': 'Avg Packet Size Orig',
        'avg_packet_size_resp': 'Avg Packet Size Resp',
        'connection_rate': 'Connection Rate',
        'is_failed_connection': 'Failed Connection Ratio',
        # Enhanced categorical features
        'duration_category': 'Duration Category',
        'traffic_pattern': 'Traffic Pattern',
        'orig_port_binned': 'Orig Port Binned',
        'resp_port_binned': 'Resp Port Binned',
        'service_binned': 'Service Binned',
        'proto': 'Protocol',
        'conn_state': 'Connection State',
        # NEW: C2 Beaconing specific features
        'small_consistent_size': 'Small Consistent Size',
        'heartbeat_candidate': 'Heartbeat Candidate',
        'periodic_score': 'Periodic Score',
        'beaconing_pattern': 'Beaconing Pattern'
    }
    
    # Clean categorical feature names (remove sklearn prefixes)
    if feature_name.startswith('cat__'):
        feature_name = feature_name.replace('cat__', '')
    
    # Handle specific categorical feature patterns
    if 'traffic_pattern_' in feature_name.lower():
        pattern_type = feature_name.lower().replace('traffic_pattern_', '').replace('cat__', '')
        return f'Traffic Pattern {pattern_type.replace("_", " ").title()}'
    
    if 'duration_category_' in feature_name.lower():
        duration_type = feature_name.lower().replace('duration_category_', '').replace('cat__', '')
        return f'Duration Category {duration_type.replace("_", " ").title()}'
    
    if 'orig_port_binned_' in feature_name.lower():
        port_type = feature_name.lower().replace('orig_port_binned_', '').replace('cat__', '')
        return f'Orig Port Binned {port_type.replace("_", " ").title()}'
    
    if 'resp_port_binned_' in feature_name.lower():
        port_type = feature_name.lower().replace('resp_port_binned_', '').replace('cat__', '')
        return f'Resp Port Binned {port_type.replace("_", " ").title()}'
    
    if 'service_binned_' in feature_name.lower():
        service_type = feature_name.lower().replace('service_binned_', '').replace('cat__', '')
        return f'Service Binned {service_type.replace("_", " ").title()}'
    
    if 'conn_state_' in feature_name.lower():
        state_type = feature_name.lower().replace('conn_state_', '').replace('cat__', '')
        return f'Conn State {state_type.upper()}'
    
    if 'proto_' in feature_name.lower():
        proto_type = feature_name.lower().replace('proto_', '').replace('cat__', '')
        return f'Proto {proto_type.upper()}'
    
    # Handle NEW C2 beaconing pattern features
    if 'beaconing_pattern_' in feature_name.lower():
        pattern_type = feature_name.lower().replace('beaconing_pattern_', '').replace('cat__', '')
        return f'Beaconing Pattern {pattern_type.replace("_", " ").title()}'
    
    # Handle group features (beacon_group_count, etc.)
    if 'beacon_group_count' in feature_name.lower():
        return 'Beacon Group Count'
    if 'beacon_group_mean_interval' in feature_name.lower():
        return 'Beacon Group Mean Interval'
    if 'beacon_group_cv' in feature_name.lower():
        return 'Beacon Group Cv'
    if 'scan_group_unique_dst_port_count' in feature_name.lower():
        return 'Scan Group Unique Dst Port Count'
    if 'scan_group_rej_ratio' in feature_name.lower():
        return 'Scan Group Rej Ratio'
    if 'ddos_group_unique_src_ip_count' in feature_name.lower():
        return 'Ddos Group Unique Src Ip Count'
    if 'ddos_group_total_bytes' in feature_name.lower():
        return 'Ddos Group Total Bytes'
    
    # Handle special features that might be missing
    if 'is_auth_port' in feature_name.lower():
        return 'Is Auth Port'
    if 'hist_r_count' in feature_name.lower():
        return 'Hist R Count'

    if 'is_failed_connection' in feature_name.lower():
        return 'Failed Connection Ratio'
    
    # Apply direct mapping if available
    feature_lower = feature_name.lower()
    for key, value in name_mapping.items():
        if key in feature_lower:
            return value
    
    # Clean up remaining names (fallback)
    clean_name = feature_name.replace('_', ' ').replace('cat__', '').title()
    return clean_name 

def clean_dns_feature_name(feature_name: str) -> str:
    """
    Clean DNS feature names for display.
    
    Args:
        feature_name: Raw feature name
        
    Returns:
        Cleaned feature name for display
    """
    try:
        # Remove common prefixes
        if feature_name.startswith('dns_'):
            feature_name = feature_name[4:]
        
        # Replace underscores with spaces
        feature_name = feature_name.replace('_', ' ')
        
        # Capitalize first letter of each word
        feature_name = ' '.join(word.capitalize() for word in feature_name.split())
        
        # Special DNS feature name mappings
        dns_mappings = {
            'query length': 'Query Length',
            'response length': 'Response Length',
            'query entropy': 'Query Entropy',
            'response entropy': 'Response Entropy',
            'subdomain count': 'Subdomain Count',
            'domain length': 'Domain Length',
            'query type': 'Query Type',
            'response type': 'Response Type',
            'ttl': 'TTL',
            'rcode': 'Response Code'
        }
        
        return dns_mappings.get(feature_name.lower(), feature_name)
        
    except Exception as e:
        logger.warning(f"Error cleaning DNS feature name '{feature_name}': {str(e)}")
        return feature_name 