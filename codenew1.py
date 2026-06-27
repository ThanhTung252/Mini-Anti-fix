import sys
import json
import subprocess
import shutil
import requests
import os

sys.stdout.reconfigure(encoding='utf-8')

# Add tools to PATH
tools_dir = os.path.join(os.getcwd(), "tools")
paths_to_add = [
    os.path.join(os.path.dirname(sys.executable), "Scripts"), # Semgrep
    os.path.join(tools_dir, "php"),                           # PHP & PHPCS
    os.path.join(tools_dir, "codeql"),                        # CodeQL
    os.path.join(tools_dir, "sonar-scanner-6.1.0.4477-windows-x64", "bin") # SonarScanner
]
os.environ["PATH"] = os.pathsep.join(paths_to_add) + os.pathsep + os.environ["PATH"]


# ============================================================
# CẤU HÌNH HỆ THỐNG
# ============================================================
GEMINI_API_KEY = "AQ.Ab8RN6J99HSTNM4ctFdDZsz_ha7rnQjUWKY1Y2_Jvwl6i_6FDA"
TARGET_DIR = "motors-car-dealership-classified-listings"

# Paths
SEMGREP_RAW_PATH = "semgrep_report.json"
PHPCS_RAW_PATH = "phpcs_report.json"
CODEQL_RAW_PATH = "codeql_report.json"
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
    if not semgrep_path: return []
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
    if not phpcs_path: return []
    res = subprocess.run([phpcs_path, "--report=json", TARGET_DIR], capture_output=True, text=True, encoding="utf-8")
    findings = []
    try:
        data = json.loads(res.stdout)
        for file_path, file_info in data.get('files', {}).items():
            for m in file_info.get('messages', []):
                line = m['line']
                findings.append({
                    "tool": "PHP_CodeSniffer",
                    "rule_id": m.get('source', 'Unknown'),
                    "file": file_path,
                    "line": line,
                    "issue": m['message'],
                    "severity": m['type'],
                    "code_snippet": extract_code_snippet(file_path, line)
                })
    except: pass
    return findings

def run_codeql():
    print(f"[*] Running CodeQL Static Analysis on folder: {TARGET_DIR}...")
    codeql_path = shutil.which("codeql")
    if not codeql_path: return []
    if os.path.exists("codeql-db"): shutil.rmtree("codeql-db")
    
    subprocess.run([codeql_path, "database", "create", "codeql-db", "--language=php", f"--source-root={TARGET_DIR}", "--overwrite"], capture_output=True, text=True, encoding="utf-8")
    subprocess.run([codeql_path, "database", "analyze", "codeql-db", "--format=json", f"--output={CODEQL_RAW_PATH}"], capture_output=True, text=True, encoding="utf-8")
    
    findings = []
    if os.path.exists(CODEQL_RAW_PATH):
        with open(CODEQL_RAW_PATH, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                for m in data:
                    f_path = m.get('mostRecentInstance', {}).get('location', {}).get('uri', 'unknown')
                    line = m.get('mostRecentInstance', {}).get('location', {}).get('startLine', 0)
                    findings.append({
                        "tool": "CodeQL",
                        "rule_id": m.get('ruleId', 'Unknown'),
                        "file": f_path,
                        "line": line,
                        "issue": m.get('message', {}).get('text', 'CodeQL Finding'),
                        "severity": "WARNING",
                        "code_snippet": extract_code_snippet(os.path.join(os.getcwd(), f_path), line)
                    })
            except: pass
    return findings

def aggregate_findings(all_findings):
    print("[*] Gom nhóm và trích xuất dữ liệu bù trừ từ các công cụ (Aggregation)...")
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
        
    # Chuyển Dict thành List
    return list(aggregated.values())

# ============================================================
# STAGE 2: AI AGENT CONSENSUS LAYER (CWE/CVE MATCHING)
# ============================================================

def ask_ai_judge(aggregated_data):
    print("[*] Đang đẩy dữ liệu Aggregated vào AI Agent (Stage 2) để phân tích đối chiếu CWE/CVE...")
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={GEMINI_API_KEY}"
    headers = {'Content-Type': 'application/json'}
    
    # Rút gọn bớt dữ liệu để tránh vượt quá limit (Giới hạn 100 lỗi đầu tiên)
    data_to_send = aggregated_data[:100]
    
    prompt = f"""
    Bạn là một AI Consensus & Security Assessment Agent cho đồ án tốt nghiệp Capstone về SAST.
    Dưới đây là danh sách các lỗi bảo mật được tổng hợp từ nhiều công cụ SAST quét trên một hệ thống. Mỗi lỗi bao gồm Code Snippet (Pattern) chính xác tại dòng xảy ra lỗi và thông tin từ các công cụ phát hiện ra nó.

    DỮ LIỆU TỔNG HỢP TỪ CÁC TOOL (Định dạng JSON):
    {json.dumps(data_to_send, indent=2)}

    YÊU CẦU XỬ LÝ SÂU:
    Với mỗi lỗi trong danh sách trên, hãy phân tích đoạn `code_snippet` và `issues` để đánh giá:
    1. Lỗi này map với mã CWE nào (hoặc CVE phổ biến nào nếu có thể)?
    2. Đánh giá Mức độ bảo mật (Severity): Critical, High, Medium, Low, hoặc False Positive.
    3. Đánh giá Mức độ ảnh hưởng (Impact Level): Hậu quả thực tế nếu bị khai thác (VD: RCE, Data Leak, XSS...).
    4. Độ uy tín (Confidence/Reputation Score): Dựa vào pattern code, bạn chắc chắn bao nhiêu % đây là True Positive?

    BẮT BUỘC TRẢ VỀ DUY NHẤT ĐỊNG DẠNG JSON SAU (Không viết chữ giải thích ngoài JSON). 
    LƯU Ý CỰC KỲ QUAN TRỌNG: Mọi đường dẫn thư mục (vd: C:\\Users\\...) hoặc ký tự Regex có chứa dấu backslash \\ đều bắt buộc phải escape đúng chuẩn JSON thành \\\\ để tránh lỗi parse JSON.
    {{
        "project": "Multi-Tool Agentic SAST Framework",
        "stage": "Stage 2: AI CWE/CVE Cross-reference & Assessment",
        "scanned_directory": "{TARGET_DIR.replace(chr(92), chr(92)+chr(92))}",
        "total_issues_analyzed": {len(data_to_send)},
        "ai_verified_vulnerabilities": [
            {{
                "file_path": "<Đường dẫn file bị lỗi>",
                "line": <số_dòng>,
                "detected_by_tools": [
                    {{ "tool": "<Tên Tool>", "rule_id": "<Mã Rule>" }}
                ],
                "cwe_cve_mapping": "<Mã CWE hoặc CVE, ví dụ CWE-79 / CWE-89>",
                "vulnerability_type": "<Tên lỗ hổng bằng tiếng Việt>",
                "security_severity": "Critical / High / Medium / Low",
                "impact_level": "<Mô tả ngắn gọn mức độ ảnh hưởng thực tế (vd: Có thể chiếm quyền điều khiển database)>",
                "confidence_score": "X%",
                "ai_justification": "<Giải thích vì sao code snippet đó gây ra lỗi và phân tích độ tin cậy>"
            }}
        ]
    }}
    """
    
    import time
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
                if "quota" in error_msg.lower() or "429" in str(response_json) or "high demand" in error_msg.lower() or "503" in str(response_json):
                    print(f"[-] Lỗi Rate Limit/Quota/High Demand API. Chờ 15s để thử lại... (Lần {attempt+1}/{max_retries})")
                    time.sleep(15)
                    continue
                print(f"[-] Lỗi API Gemini: {error_msg}")
                return None
            raw_text = response_json['candidates'][0]['content']['parts'][0]['text'].strip()
            if raw_text.startswith("```json"): raw_text = raw_text[7:]
            elif raw_text.startswith("```"): raw_text = raw_text[3:]
            if raw_text.endswith("```"): raw_text = raw_text[:-3]
            return json.loads(raw_text.strip(), strict=False)
        except Exception as e:
            print(f"[-] Lỗi kết nối hoặc xử lý AI: {e}")
            return None
    print("[-] Quá số lần thử lại. Thất bại.")
    return None

# ============================================================
# MAIN PIPELINE EXECUTION
# ============================================================

def main():
    print("="*70)
    print(" PIPELINE SAST 2.0: RICH PATTERN EXTRACTION & AI CWE ASSESSMENT ")
    print("="*70)
    
    if not os.path.exists(TARGET_DIR):
        print(f"[-] Không tìm thấy thư mục: {TARGET_DIR}")
        return

    # ---------------------------------------------------------
    # STAGE 1: RAW DATA COLLECTION & AGGREGATION
    # ---------------------------------------------------------
    print("\n[+] BẮT ĐẦU STAGE 1: Quét và thu thập dữ liệu...")
    semgrep_findings = run_semgrep()
    phpcs_findings = run_phpcs()
    codeql_findings = run_codeql()
    
    with open(SEMGREP_RAW_PATH, "w", encoding="utf-8") as f:
        json.dump({"findings": semgrep_findings}, f, indent=4, ensure_ascii=False)
    with open(PHPCS_RAW_PATH, "w", encoding="utf-8") as f:
        json.dump({"findings": phpcs_findings}, f, indent=4, ensure_ascii=False)
        
    all_findings = semgrep_findings + phpcs_findings + codeql_findings
    aggregated_data = aggregate_findings(all_findings)
    
    with open(STAGE1_AGGREGATED_PATH, "w", encoding="utf-8") as f:
        json.dump(aggregated_data, f, indent=4, ensure_ascii=False)
        
    print("\n[+] HOÀN THÀNH STAGE 1:")
    print(f"    - Tìm thấy tổng cộng: {len(all_findings)} issues thô từ các tools.")
    print(f"    - Sau khi gom nhóm (trùng file/line), còn lại: {len(aggregated_data)} unique issues.")
    print(f"    - File tổng hợp Stage 1 đã lưu tại: {STAGE1_AGGREGATED_PATH}")

    if not aggregated_data:
        print("[-] Không có lỗi nào được phát hiện để phân tích tiếp.")
        return

    # ---------------------------------------------------------
    # STAGE 2: AI CWE/CVE CROSS-REFERENCE & ASSESSMENT
    # ---------------------------------------------------------
    print("\n[+] BẮT ĐẦU STAGE 2: AI phân tích đối chiếu bảo mật...")
    final_json = ask_ai_judge(aggregated_data)
    
    print("="*70)
    if final_json:
        print("[+] KẾT QUẢ ĐỒNG THUẬN CUỐI CÙNG (AI CONSENSUS):")
        with open(FINAL_REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(final_json, f, indent=4, ensure_ascii=False)
        print(f"\n[+] ĐÃ XUẤT BÁO CÁO CẤP CAO THÀNH CÔNG RA FILE: {FINAL_REPORT_PATH}")
    else:
        print("[-] Pipeline không thể hoàn thành bước AI Consensus.")
    print("="*70)

if __name__ == "__main__":
    main()