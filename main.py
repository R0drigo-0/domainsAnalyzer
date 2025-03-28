#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from requests.cookies import RequestsCookieJar
from bs4 import BeautifulSoup

from analyze import process_parquet

from concurrent.futures import ThreadPoolExecutor
import concurrent.futures

import pandas as pd

import requests
import datetime
import argparse
import logging
import time
import json
import sys
import re
import os

import urllib3

urllib3.disable_warnings(
    urllib3.exceptions.InsecureRequestWarning
)  # To avoid SSL warnings


class NewDomains:
    def __init__(self):
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s - %(levelname)s: %(message)s",
            handlers=[logging.StreamHandler()],
        )

        # Get logger for this class
        self.logger = logging.getLogger(__name__)

        self.open_intel_zoneFile_url = (
            "https://www.openintel.nl/download/forward-dns/basis=zonefile"
        )

        self.stop_requested = False

    def convert_parquet_to_csv(self, parquet_file: str, output_csv: str = None):
        """Convert parquet file to CSV format"""
        try:
            if "pd" not in globals():
                self.logger.error("pandas not installed. Cannot convert to CSV.")
                return None

            if not output_csv:
                output_csv = parquet_file.replace(".parquet", ".csv")

            if os.path.exists(output_csv):
                self.logger.info(
                    f"CSV file {output_csv} already exists, skipping conversion."
                )
                return output_csv

            self.logger.info(f"Converting {parquet_file} to CSV...")

            # Read the parquet file
            df = pd.read_parquet(parquet_file)

            # Write to CSV
            df.to_csv(output_csv, index=False)

            self.logger.info(f"Successfully converted to {output_csv}")
            return output_csv
        except Exception as e:
            self.logger.error(f"Error converting parquet to CSV: {e}")
            return None

    def _download_parquet_file(self, url: str, file_path: str, convert_to_csv:bool=True):
        """Download a parquet file and optionally convert it to CSV"""
        if os.path.exists(file_path):
            self.logger.info(f"File {file_path} already exists, skipping download.")
            # If CSV conversion is requested, check if CSV exists
            if convert_to_csv:
                csv_path = file_path.replace(".parquet", ".csv")
                if not os.path.exists(csv_path):
                    self.convert_parquet_to_csv(file_path)
            return

        try:
            res = requests.get(url, stream=True, verify=False)
            res.raise_for_status()

            with open(file_path, "wb") as f:
                for chunk in res.iter_content(chunk_size=8192):
                    f.write(chunk)

            self.logger.info(f"Downloaded {file_path}")

            if convert_to_csv:
                self.convert_parquet_to_csv(file_path)

        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to download {url}: {e}")

    def _fetch_open_intel_zoneFile(
        self,
        date: str = None,
        all_active: bool = True,
        max_workers: int = 10,
        sources_to_process: str = None,
        max_days_per_month: int = None,
        convert_to_csv: bool = True,
    ):
        jar = RequestsCookieJar()
        jar.set("openintel-data-agreement-accepted", "true")

        # Track overall progress
        self.total_files = 0
        self.downloaded_files = 0

        def get_links_from_url(url, prefix, base_url="https://www.openintel.nl"):
            if self.stop_requested:
                return []

            self.logger.info(f"Fetching links from {url} with prefix {prefix}")
            try:
                response = requests.get(url, cookies=jar, verify=False, timeout=30)
                response.raise_for_status()

                soup = BeautifulSoup(response.text, "html.parser")
                table = soup.find("table", id="index_table")

                if not table:
                    self.logger.error(f"No table found at {url}")
                    return []

                links = []
                for href in table.find_all("a", href=True):
                    if self.stop_requested:
                        return links

                    href_text = href.get_text(strip=True)
                    if href_text.startswith(prefix):
                        link_url = f"{base_url}{href['href']}"
                        links.append((href_text, link_url))
                        self.logger.info(
                            f"Found {prefix} item: {href_text} with URL: {link_url}"
                        )

                if date and prefix == "day=":
                    target_day = f"day={date.split('-')[2]}"
                    links = [link for link in links if link[0] == target_day]

                if max_days_per_month and prefix == "day=":
                    links = links[:max_days_per_month]

                return links
            except Exception as e:
                self.logger.error(f"Error fetching links from {url}: {e}")
                return []

        def process_day(day_name, day_url):
            """Process a single day and download parquet files"""
            if self.stop_requested:
                return

            self.logger.info(f"Processing day: {day_name}")
            try:
                response = requests.get(day_url, cookies=jar, verify=False, timeout=30)
                response.raise_for_status()

                soup = BeautifulSoup(response.text, "html.parser")
                table = soup.find("table", id="index_table")

                if not table:
                    self.logger.error(f"No table found at {day_url}")
                    return

                for href in table.find_all("a", href=True):
                    if self.stop_requested:
                        return

                    href_url = href.get("href")
                    if href_url and href_url.endswith(".parquet"):
                        if href_url.startswith("http"):
                            parquet_url = href_url
                        else:
                            parquet_url = f"https://www.openintel.nl{href_url}"

                        filename = os.path.basename(href_url)
                        self.logger.info(f"Found parquet file: {parquet_url}")

                        os.makedirs("./zoneFile", exist_ok=True)
                        self._download_parquet_file(
                            parquet_url, f"./zoneFile/{filename}", True
                        )
                        self.downloaded_files += 1
                        self.logger.info(
                            f"Progress: {self.downloaded_files}/{self.total_files} files"
                        )
            except Exception as e:
                self.logger.error(f"Error processing day {day_name}: {e}")

        sources = get_links_from_url(self.open_intel_zoneFile_url, "source=")
        if not sources:
            self.logger.error("No source links found.")
            return

        if sources_to_process:
            sources = [s for s in sources if s[0] in sources_to_process]

        if not self.stop_requested:
            self.logger.info("Calculating total files to download...")
            for source_name, source_url in sources:
                if self.stop_requested:
                    break

                years = get_links_from_url(source_url, "year=")
                for year_name, year_url in years:
                    if self.stop_requested:
                        break

                    if date and not year_name.endswith(date.split("-")[0]):
                        continue

                    months = get_links_from_url(year_url, "month=")
                    for month_name, month_url in months:
                        if self.stop_requested:
                            break

                        if date and not month_name.endswith(date.split("-")[1]):
                            continue

                        days = get_links_from_url(month_url, "day=")
                        for day_name, day_url in days:
                            if self.stop_requested:
                                break

                            self.total_files += 1

        self.logger.info(f"Starting download of approximately {self.total_files} files")

        for source_name, source_url in sources:
            if self.stop_requested:
                self.logger.info("Stop requested, exiting source processing")
                break

            self.logger.info(f"Processing source: {source_name}")

            years = get_links_from_url(source_url, "year=")
            if not years:
                self.logger.info(f"No years found for {source_name}")
                continue

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                if self.stop_requested:
                    break

                if date:
                    years = [y for y in years if y[0].endswith(date.split("-")[0])]

                futures = []
                for year_name, year_url in years:
                    self.logger.info(f"Processing year: {year_name}")

                    months = get_links_from_url(year_url, "month=")
                    if not months:
                        self.logger.info(f"No months found for {year_name}")
                        continue

                    if date:
                        months = [
                            m for m in months if m[0].endswith(date.split("-")[1])
                        ]

                    for month_name, month_url in months:
                        if self.stop_requested:
                            break

                        self.logger.info(f"Processing month: {month_name}")

                        days = get_links_from_url(month_url, "day=")
                        if not days:
                            self.logger.info(f"No days found for {month_name}")
                            continue

                        for day_name, day_url in days:
                            if self.stop_requested:
                                break
                            futures.append(
                                executor.submit(process_day, day_name, day_url)
                            )

                for future in concurrent.futures.as_completed(futures):
                    try:
                        future.result()
                        if self.stop_requested:
                            for f in futures:
                                if not f.done():
                                    f.cancel()
                            break
                    except Exception as e:
                        self.logger.error(f"Error in day processing: {e}")

    def _fetch_open_intel_topList(self, date: str, all_active: bool = True):
        pass

    def _fetch_open_intel_cctlds(self, date: str, all_active: bool = True):
        pass

    def _fetch_open_intel_ctLog(self, date: str, all_active: bool = True):
        pass

    def _fetch_open_intel_rirs_rdns(self, date: str, all_active: bool = True):
        pass

    def _fetch_open_intel_whois(self, date: str, all_active: bool = True):
        pass

    def fetch_open_intel(self):
        pass    

    def run(self, date=None, sources=None, max_days=None, convert_to_csv=True):
        self.logger.info("Starting domain fetcher")
        paths = self._fetch_open_intel_zoneFile(
            date=date,
            all_active=True,
            max_workers=10,
            sources_to_process=sources,
            max_days_per_month=max_days,
            convert_to_csv=convert_to_csv,
        )
        


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Fetch domain information from OpenINTEL"
    )

    parser.add_argument("--date", type=str, help="Specific date to fetch (YYYY-MM-DD)")
    parser.add_argument(
        "--sources",
        type=str,
        nargs="+",
        help="Specific sources to process (e.g., 'source=com')",
    )
    parser.add_argument(
        "--max-days", type=int, help="Maximum days per month to process"
    )
    parser.add_argument("--csv", action="store_true", help="Convert .parquet to .csv")

    args = parser.parse_args()

    worker = None
    try:
        worker = NewDomains()
        worker.run(
            date=args.date,
            sources=args.sources,
            max_days=args.max_days,
            convert_to_csv=args.csv,
        )
    except KeyboardInterrupt:
        print("\n\nKeyboard interrupt received. Shutting down gracefully...")
        if worker:
            worker.stop_requested = True
    finally:
        print("Cleaning up resources...")
        logging.shutdown()


if __name__ == "__main__":
    sys.exit(main())
