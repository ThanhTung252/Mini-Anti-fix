import sys
import json
import subprocess
import shutil
import requests
import os
import time

sys.stdout.reconfigure(encoding='utf-8')

# Add tools to PATH
tools_dir = os.path.join(os.getcwd(), "tools")
paths_to_add = [
    os.path.join(os.path.dirname(sys.executable), "Scripts"), # Semgrep
    os.path.join(tools_dir, "php"),                           # PHP & PHPCS
]
os.environ["PATH"] = os.pathsep.join(paths_to_add) + os.pathsep + os.environ["PATH"]

# ============================================================
# CẤU HÌNH HỆ THỐNG
# ============================================================
GEMINI_API_KEY = "AQ.Ab8RN6J99HSTNM4ctFdDZsz_ha7rnQjUWKY1Y2_Jvwl6i_6FDA" # Hãy đảm bảo key này là chính xác (Thường bắt đầu bằng AIzaSy...)
TARGET_DIR = "motors-car-dealership-classified-listings"

# Paths
SEMGREP_RAW_PATH = "semgrep_report.json"
PHPCS_RAW_PATH = "phpcs_report.json"
STAGE1_AGGREGATED_PATH = "stage1_aggregated_report.json"
FINAL_REPORT_PATH = "final_consensus_report.json"

# ============================================================
# HELPER: TRÍCH XUẤT CODE SNIPPET (PATTERN)
# ============================================================
def extract_code_snippet(file_path, line_number, context_lines=5):
    """Trích xuất mã nguồn xung quanh dòng bị lỗi để lấy Pattern."""
    if not os.path.exists(file_path) or not isinstance(line_number, int) or line_number <= 0:
        return "Source code not available or invalid line."
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            snippet = []
            for i in range(start, end):
                prefix = ">> " if i == line_number - 1 else "   "
                snippet.append(f"{i+1:4d} {prefix}{lines[i].rstrip()}")
            return "\n".join(snippet)
    except Exception:
        return "Error reading source code."

# ============================================================
# STAGE 1: RAW DATA COLLECTION LAYER (QUÉT & GOM NHÓM)
# ============================================================

def run_semgrep():
    print(f"[*] Running Semgrep on folder: {TARGET_DIR}...")
    semgrep_path = shutil.which("semgrep")
    if not semgrep_path: 
        print("[-] Lỗi: Không tìm thấy Semgrep trong hệ thống.")
        return []
    res = subprocess.run([semgrep_path, "--config=auto", "--json", TARGET_DIR], capture_output=True, text=True, encoding="utf-8")
    findings = []
    try:
        data = json.loads(res.stdout)
        for m in data.get('results', []):
            f_path = m.get('path')
            line = m['start']['line']
            findings.append({
                "tool": "Semgrep",
                "rule_id": m.get('check_id', 'Unknown'),
                "file": f_path,
                "line": line,
                "issue": m['extra']['message'],
                "severity": m['extra']['severity'],
                "code_snippet": extract_code_snippet(f_path, line)
            })
    except: pass
    return findings

def run_phpcs():
    print(f"[*] Running PHP_CodeSniffer on folder: {TARGET_DIR}...")
    phpcs_path = shutil.which("phpcs")
    if not phpcs_path: 
        print("[-] Lỗi: Không tìm thấy PHPCS trong hệ thống.")
        return []
    res = subprocess.run([phpcs_path, "--report=json", TARGET_DIR], capture_output=True, text=True, encoding="utf-8")
    findings = []
    try:
        data = json.loads(res.stdout)
        for file_path, file_info in data.get('files', {}).items():
            for m in file_info.get('messages', []):
                line = m['line']
                findings.append({
                    "tool": "PHPCS",
                    "rule_id": m.get('source', 'Unknown'),
                    "file": file_path,
                    "line": line,
                    "issue": m['message'],
                    "severity": m['type'],
                    "code_snippet": extract_code_snippet(file_path, line)
                })
    except: pass
    return findings

def aggregate_findings(all_findings):
    print("[*] Gom nhóm kết quả giữa Semgrep và PHPCS...")
    aggregated = {}
    
    for f in all_findings:
        key = f"{f['file']}::LINE_{f['line']}"
        if key not in aggregated:
            aggregated[key] = {
                "file": f['file'],
                "line": f['line'],
                "detected_by": [],
                "issues": [],
                "code_snippet": f['code_snippet']
            }
        
        aggregated[key]["detected_by"].append({
            "tool": f["tool"],
            "rule_id": f["rule_id"]
        })
        aggregated[key]["issues"].append(f"[{f['tool']}] {f['issue']}")
        
    return list(aggregated.values())

# ============================================================
# STAGE 2: AI AGENT CONSENSUS LAYER
# ============================================================

def ask_ai_judge(aggregated_data):
    print("[*] Đang đẩy dữ liệu vào AI Agent (Stage 2) để so sánh và quyết định...")
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    headers = {'Content-Type': 'application/json'}
    
    # Rút gọn bớt dữ liệu để tránh vượt quá limit API của bản Free (Giữ 80 lỗi đầu tiên)
    data_to_send = aggregated_data[:80]
    
    prompt = f"""
    Bạn là một AI Consensus & Security Assessment Agent.
    Nhiệm vụ của bạn là so sánh kết quả quét lỗi từ 2 công cụ: Semgrep (mạnh về bảo mật, luồng dữ liệu) và PHPCS (mạnh về cú pháp, chuẩn code).
    
    DỮ LIỆU TỔNG HỢP TỪ 2 TOOL (Định dạng JSON):
    {json.dumps(data_to_send, indent=2)}

    YÊU CẦU XỬ LÝ SÂU:
    Với mỗi lỗi trong danh sách trên, hãy phân tích đoạn `code_snippet` và đưa ra quyết định:
    1. So sánh: Lỗi này do Semgrep hay PHPCS báo chính xác hơn? Cảnh báo nào là False Positive (báo động giả)?
    2. Nếu là lỗi bảo mật thực sự (Ví dụ CWE/CVE), hãy phân tích mức độ nghiêm trọng (Critical/High/Medium/Low).
    3. Nếu chỉ là lỗi cú pháp (Styling), hãy dán nhãn là "Code Quality".
    4. Chỉ giữ lại những lỗi mà bạn đánh giá là thực sự cần thiết phải sửa.

    BẮT BUỘC TRẢ VỀ DUY NHẤT ĐỊNH DẠNG JSON SAU (Tuyệt đối không viết text giải thích ngoài JSON, escape dấu backslash cẩn thận):
    {{
        "project": "Semgrep vs PHPCS Agentic Assessment",
        "scanned_directory": "{TARGET_DIR.replace(chr(92), chr(92)+chr(92))}",
        "total_issues_analyzed": {len(data_to_send)},
        "ai_verified_vulnerabilities": [
            {{
                "file_path": "<Đường dẫn file bị lỗi>",
                "line": <số_dòng>,
                "detected_by_tools": [
                    {{ "tool": "<Tên Tool>", "rule_id": "<Mã Rule>" }}
                ],
                "cwe_mapping": "<Mã CWE hoặc 'Code Quality'>",
                "vulnerability_type": "<Tên lỗ hổng bằng tiếng Việt>",
                "security_severity": "Critical / High / Medium / Low / Info",
                "winning_tool": "<Semgrep / PHPCS / Both - Tool nào đánh giá đúng nhất>",
                "ai_justification": "<Giải thích vì sao chọn tool này và loại tool kia, dựa trên code snippet>"
            }}
        ]
    }}
    """
    
    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"responseMimeType": "application/json"}
    }
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            response = requests.post(url, headers=headers, json=payload)
            response_json = response.json()
            if 'error' in response_json:
                error_msg = response_json['error']['message']
                if "quota" in error_msg.lower() or "429" in str(response_json) or "503" in str(response_json):
                    print(f"[-] Lỗi API Limit. Chờ 15s để thử lại... (Lần {attempt+1}/{max_retries})")
                    time.sleep(15)
                    continue
                print(f"[-] Lỗi API Gemini: {error_msg}")
                return None
            
            raw_text = response_json['candidates'][0]['content']['parts'][0]['text'].strip()
            # Xử lý làm sạch chuỗi markdown JSON nếu API trả về thừa
            if raw_text.startswith("
http://googleusercontent.com/immersive_entry_chip/0
http://googleusercontent.com/immersive_entry_chip/1
http://googleusercontent.com/immersive_entry_chip/2