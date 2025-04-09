from requests.cookies import RequestsCookieJar
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from typing import Dict
import requests
import logging
import urllib3
import json
import time
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class OpenIntelCrawler:
    def __init__(self, cookies):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s: %(message)s",
            handlers=[logging.StreamHandler()],
        )
        self.logger = logging.getLogger("OpenIntelCrawler")
        self.cookies = cookies
        self.base_url = "https://www.openintel.nl"
        self.visited_urls = set()

    def extract_urls_from_table(self, html_content: str) -> list:
        soup = BeautifulSoup(html_content, 'html.parser')
        table = soup.find('table', id='index_table')
        if not table:
            return []
        
        urls = []
        for cell in table.find_all('td', class_='ellipsis'):
            anchor = cell.find('a')
            if anchor and anchor.has_attr('href'):
                absolute_url = urljoin(self.base_url, anchor['href'])
                urls.append(absolute_url)
        return urls
    
    def get_urls_from_webpage(self, url: str) -> list:
        if url in self.visited_urls:
            return []
            
        self.visited_urls.add(url)
        self.logger.info(f"Fetching: {url}")
        
        try:
            response = requests.get(url, cookies=self.cookies, verify=False, timeout=10)
            if response.status_code == 200:
                return self.extract_urls_from_table(response.text)
            else:
                self.logger.error(f"Failed to retrieve: {url}, status: {response.status_code}")
                return []
        except Exception as e:
            self.logger.error(f"Error fetching {url}: {str(e)}")
            return []
    
    def crawl_recursively(self, start_url: str, max_depth: int = 9223372036854775807, delay: float = 0) -> Dict:
        self.visited_urls.clear()
        
        def _crawl(url: str, depth: int) -> Dict:
            if depth > max_depth:
                return {}
                
            urls = self.get_urls_from_webpage(url)
            time.sleep(delay)
            
            result = {}
            for child_url in urls:
                path = child_url
                result[path] = _crawl(child_url, depth + 1)
            return result
        
        return _crawl(start_url, 1)

    def print_url_structure(self, structure: Dict, indent: int = 0) -> None:
        for url, children in structure.items():
            print('  ' * indent + f"{url}")
            if children:
                self.print_url_structure(children, indent + 1)

    def store_url_structure(self, structure: Dict, filename: str = "url_structure.json") -> None:
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(structure, f, indent=2)
            self.logger.info(f"URL structure saved to {os.path.abspath(filename)}")
        except Exception as e:
            self.logger.error(f"Error saving URL structure: {e}")


if __name__ == "__main__":
    cookies = {"openintel-data-agreement-accepted": "true"}
    base_url = "https://www.openintel.nl/download"
    crawler = OpenIntelCrawler(cookies)
    
    url_structure = crawler.crawl_recursively(base_url, max_depth=2)
    
    print("\nURL Structure:")
    crawler.print_url_structure(url_structure)
    
    print(f"\nTotal URLs visited: {len(crawler.visited_urls)}")
    
    # Save URL structure to JSON file
    crawler.store_url_structure(url_structure)