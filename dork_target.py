import requests
from bs4 import BeautifulSoup
import time
import random
from urllib.parse import quote
from colorama import Fore, Style, init
import argparse
from datetime import datetime
import csv
import validators
from tqdm import tqdm
from fake_useragent import UserAgent
import sys
from requests.exceptions import RequestException
import logging

# Inisialisasi colorama dan logging
init()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DorkScanner:
    def __init__(self):
        self.ua = UserAgent()
        self.results = []
        self.min_delay = 7
        self.max_delay = 15
        self.session = requests.Session()
        self.proxies = self.load_proxies()
        self.current_proxy_index = 0
        self.consecutive_errors = 0
        self.max_retries = 3

    def load_proxies(self):
        """Load proxy list dari file atau gunakan default"""
        default_proxies = [
            None,  # No proxy
            'socks5h://127.0.0.1:9050'  # Tor proxy if available
        ]
        try:
            with open('proxies.txt', 'r') as f:
                return [line.strip() for line in f if line.strip()] + default_proxies
        except FileNotFoundError:
            return default_proxies

    def rotate_proxy(self):
        """Rotasi proxy"""
        if self.proxies:
            self.current_proxy_index = (self.current_proxy_index + 1) % len(self.proxies)
            current_proxy = self.proxies[self.current_proxy_index]
            if current_proxy:
                return {'http': current_proxy, 'https': current_proxy}
        return None

    def get_headers(self):
        """Generate random headers"""
        return {
            'User-Agent': self.ua.random,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }

    def smart_delay(self):
        """Implementasi delay yang lebih cerdas"""
        base_delay = random.uniform(self.min_delay, self.max_delay)
        jitter = random.uniform(-2, 2)
        return max(5, base_delay + jitter)

    def handle_rate_limit(self):
        """Menangani rate limiting"""
        self.consecutive_errors += 1
        if self.consecutive_errors >= 3:
            logger.warning("Multiple errors detected, rotating proxy and increasing delay...")
            self.rotate_proxy()
            self.min_delay += 5
            self.max_delay += 5
            time.sleep(45)  # Extended cooldown
            self.consecutive_errors = 0
        else:
            time.sleep(self.smart_delay())

    def generate_dorks(self, domain):
        """Generate dorks untuk domain spesifik"""
        return [
            f'site:{domain} filetype:pdf',
            f'site:{domain} inurl:admin',
            f'site:{domain} inurl:login',
            f'site:{domain} filetype:xls',
            f'site:{domain} filetype:txt',
            f'site:{domain} inurl:config',
            f'site:{domain} intext:password',
            f'site:{domain} intitle:"index of"',
            f'site:{domain} inurl:wp-content',
            f'site:{domain} inurl:phpinfo',
            f'site:{domain} ext:sql',
            f'site:{domain} inurl:backup',
            f'site:{domain} inurl:.env',
            f'site:{domain} inurl:wp-config',
            f'site:{domain} inurl:.git',
            f'site:{domain} inurl:api',
            f'site:{domain} filetype:log',
            f'site:{domain} inurl:debug',
            f'site:{domain} intext:error',
            f'site:{domain} inurl:setup'
        ]

    def categorize_finding(self, url, dork):
        """Kategorisasi temuan berdasarkan tipe"""
        if 'filetype:pdf' in dork:
            return 'Document - PDF'
        elif 'filetype:xls' in dork:
            return 'Document - Spreadsheet'
        elif 'admin' in url.lower() or 'login' in url.lower():
            return 'Access Point'
        elif 'config' in url.lower() or '.env' in url.lower():
            return 'Configuration'
        elif 'backup' in url.lower() or '.sql' in url.lower():
            return 'Backup Files'
        elif 'wp-' in url.lower():
            return 'WordPress'
        elif 'api' in url.lower():
            return 'API Endpoint'
        elif 'error' in url.lower() or 'debug' in url.lower():
            return 'Debug Information'
        return 'Other'

    def scan_url(self, url, dork):
        """Scan single URL dan kategorisasi"""
        try:
            response = requests.get(url, headers=self.headers, timeout=5)
            return {
                'url': url,
                'status': response.status_code,
                'category': self.categorize_finding(url, dork),
                'dork': dork,
                'content_length': len(response.content)
            }
        except Exception as e:
            return {
                'url': url,
                'status': 'Error',
                'category': 'Error',
                'dork': dork,
                'error': str(e)
            }

    def google_search(self, dork, pages=1):
        """Melakukan pencarian Google dengan penanganan error yang lebih baik"""
        results = []
        for page in range(pages):
            retry_count = 0
            while retry_count < self.max_retries:
                try:
                    time.sleep(self.smart_delay())
                    
                    start = page * 10
                    search_url = f"https://www.google.com/search?q={quote(dork)}&start={start}"
                    
                    headers = self.get_headers()
                    proxies = self.rotate_proxy()
                    
                    response = self.session.get(
                        search_url,
                        headers=headers,
                        proxies=proxies,
                        timeout=10
                    )
                    
                    if "Our systems have detected unusual traffic" in response.text:
                        logger.warning("Google detection triggered, rotating proxy and increasing delay...")
                        self.handle_rate_limit()
                        retry_count += 1
                        continue
                    
                    soup = BeautifulSoup(response.text, 'html.parser')
                    search_results = soup.find_all('div', class_='yuRUbf')
                    
                    if not search_results:
                        logger.warning("No results found, might be blocked...")
                        retry_count += 1
                        continue
                    
                    for result in search_results:
                        link = result.find('a').get('href')
                        results.append({'url': link, 'dork': dork})
                    
                    self.consecutive_errors = 0  # Reset error counter on success
                    break
                    
                except RequestException as e:
                    logger.error(f"Request error: {str(e)}")
                    self.handle_rate_limit()
                    retry_count += 1
                except Exception as e:
                    logger.error(f"Unexpected error: {str(e)}")
                    retry_count += 1
                
            if retry_count >= self.max_retries:
                logger.error(f"Max retries reached for dork: {dork}")
                
        return results

    def scan_with_chunks(self, dorks, chunk_size=5):
        """Scan dorks in chunks to avoid overwhelming"""
        all_results = []
        chunks = [dorks[i:i + chunk_size] for i in range(0, len(dorks), chunk_size)]
        
        for chunk_num, chunk in enumerate(chunks, 1):
            logger.info(f"\nProcessing chunk {chunk_num}/{len(chunks)}")
            
            for dork in chunk:
                print(f"\n{Fore.YELLOW}[*] Scanning with dork: {dork}{Style.RESET_ALL}")
                results = self.google_search(dork, pages=2)
                
                for result in results:
                    scan_result = self.scan_url(result['url'], result['dork'])
                    all_results.append(scan_result)
                    
                    status_color = Fore.GREEN if scan_result['status'] == 200 else Fore.RED
                    print(f"{status_color}[{scan_result['category']}] {scan_result['url']}{Style.RESET_ALL}")
            
            # Cooldown between chunks
            if chunk_num < len(chunks):
                cooldown = random.uniform(20, 30)
                logger.info(f"Cooling down for {cooldown:.2f} seconds...")
                time.sleep(cooldown)
        
        return all_results

    def save_results(self, filename):
        """Menyimpan hasil ke CSV"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{filename}_{timestamp}.csv"
        
        with open(filename, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['URL', 'Category', 'Status', 'Dork', 'Content Length'])
            for result in self.results:
                writer.writerow([
                    result['url'],
                    result['category'],
                    result['status'],
                    result['dork'],
                    result.get('content_length', 'N/A')
                ])
        
        print(f"{Fore.GREEN}Results saved to {filename}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Enhanced Domain-specific Google Dork Scanner')
    parser.add_argument('-d', '--domain', help='Target domain to scan', required=True)
    parser.add_argument('-o', '--output', help='Output file name', default='dork_results')
    parser.add_argument('--chunk-size', type=int, default=5, help='Number of dorks per chunk')
    
    args = parser.parse_args()
    
    if not validators.domain(args.domain):
        print(f"{Fore.RED}Invalid domain format!{Style.RESET_ALL}")
        return
    
    scanner = DorkScanner()
    dorks = scanner.generate_dorks(args.domain)
    
    print(f"{Fore.CYAN}[*] Starting enhanced scan for domain: {args.domain}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}[*] Generated {len(dorks)} dorks{Style.RESET_ALL}")
    
    try:
        all_results = scanner.scan_with_chunks(dorks, args.chunk_size)
        scanner.results = all_results
        scanner.save_results(args.output)
        
        # Print summary
        categories = {}
        for result in all_results:
            cat = result['category']
            categories[cat] = categories.get(cat, 0) + 1
        
        print("\nScan Summary:")
        for category, count in categories.items():
            print(f"{Fore.CYAN}{category}: {count} findings{Style.RESET_ALL}")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan terminated by user{Style.RESET_ALL}")
        scanner.save_results(f"{args.output}_partial")
        sys.exit(1)

if __name__ == "__main__":
    main()
