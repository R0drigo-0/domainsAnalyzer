from requests.cookies import RequestsCookieJar
from datetime import datetime
from bs4 import BeautifulSoup

import requests
import logging
import urllib3
import asyncio
import aiohttp
import json

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)  # To avoid SSL warnings


class OpenIntelCrawler:
    def __init__(self, cookies):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s: %(message)s",
            handlers=[
                logging.StreamHandler(),
            ],
        )
        self.logger = logging.getLogger("OpenIntelCrawler")
        self.cookies = cookies
        self.base_openintel_url = "https://www.openintel.nl"
        self.visited_urls = set()
        self.unique_lock = asyncio.Lock()

    def get_links_from_url(
        self,
        url,
        source,
        date=None,
        max_days=None,
        base_url="https://www.openintel.nl/download",
    ):
        self.logger.info(f"Fetching links from {url} with source {source}")
        try:
            response = requests.get(url, cookies=self.cookies, verify=False, timeout=30)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, "html.parser")
            table = soup.find("table", id="index_table")

            if not table:
                self.logger.error(f"No table found at {url}")
                return []

            links = []
            for href in table.find_all("a", href=True):

                href_text = href.get_text(strip=True)
                if href_text.startswith(source):
                    link_url = f"{base_url}{href['href']}"
                    links.append((href_text, link_url))

            # Apply filtering
            if date and source == "day=":
                target_day = f"day={date.split('-')[2]}"
                links = [link for link in links if link[0] == target_day]

            if max_days and source == "day=":
                links = links[:max_days]

            return links
        except Exception as e:
            self.logg7er.error(f"Error fetching links from {url}: {e}")
            return []

    async def store_openIntel_directory_structure(
        self,
        base_url="https://www.openintel.nl/download/",
        output_file="openintel_structure.json",
    ):
        async with self.unique_lock:
            if base_url in self.visited_urls:
                self.logger.info(f"Already processed {base_url}. Skipping...")
                return {"url": base_url, "children": {}}
            self.visited_urls.add(base_url)
        self.logger.info(
            f"Starting to crawl OpenINTEL directory structure from {base_url}"
        )
        start_time = datetime.now()
        node = {"url": base_url, "children": {}}
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(
                cookies=self.cookies, timeout=timeout
            ) as session:
                async with session.get(base_url, ssl=False) as response:
                    response.raise_for_status()
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")
                    table = soup.find("table", id="index_table")
                    if not table:
                        self.logger.error(f"No table found at {base_url}")
                        return node
                    tasks = []
                    for td in table.find_all("td", class_="ellipsis"):
                        a = td.find("a", href=True)
                        if a:
                            href = a.get("href")
                            text = a.get_text(strip=True)
                            url = f"{self.base_openintel_url}{href}"
                            self.logger.info(f"Found link: {text} -> {url}")
                            if url.lower().endswith(".parquet"):
                                node["children"][text] = {"url": url, "children": {}}
                            else:
                                task = asyncio.create_task(
                                    self.store_openIntel_directory_structure(
                                        base_url=url, output_file=output_file
                                    )
                                )
                                tasks.append((text, task))
                    if tasks:
                        results = await asyncio.gather(
                            *(t[1] for t in tasks), return_exceptions=True
                        )
                        for (text, _), result in zip(tasks, results):
                            if not isinstance(result, Exception):
                                node["children"][text] = result
                    self.logger.info(f"Completed processing {base_url}")
        except Exception as e:
            self.logger.error(f"Error processing {base_url}: {e}")
        duration = (datetime.now() - start_time).total_seconds()
        self.logger.info(f"Completed in {duration:.2f} seconds")
        return node


if __name__ == "__main__":
    cookies = {"openintel-data-agreement-accepted": "true"}
    crawler = OpenIntelCrawler(cookies)
    asyncio.run(
        crawler.store_openIntel_directory_structure(
            base_url="https://www.openintel.nl/download/forward-dns/basis=zonefile/",
            output_file="openintel_structure_zoneFile.json",
        )
    )
