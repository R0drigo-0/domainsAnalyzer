#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from requests.cookies import RequestsCookieJar
from bs4 import BeautifulSoup


from concurrent.futures import ThreadPoolExecutor
from analyze import process_parquet

import pyarrow.parquet as pq
import pandas as pd


import concurrent.futures
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
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler("worker.log", mode="a"),
            ],
        )

        self.logger = logging.getLogger(__name__)

        self.open_intel_zoneFile_url = (
            "https://www.openintel.nl/download/forward-dns/basis=zonefile"
        )

        self.stop_requested = False
        self.chunk_size = 8192

    def convert_parquet_to_csv_chunked(self, parquet_file: str, chunksize: int = 8192):
        try:
            file_path = os.path.abspath(parquet_file)
            file_dir = os.path.dirname(file_path)
            base_name = os.path.basename(parquet_file).replace(".parquet", "")

            output_dir = os.path.join(file_dir, base_name)
            os.makedirs(output_dir, exist_ok=True)

            manifest_path = os.path.join(output_dir, "manifest.json")
            if os.path.exists(manifest_path):
                self.logger.info(
                    f"File {parquet_file} already processed, manifest found at {manifest_path}"
                )
                with open(manifest_path, "r") as f:
                    return json.load(f)

            file_size_mb = os.path.getsize(parquet_file) / (1024 * 1024)
            self.logger.info(
                f"Processing parquet file: {parquet_file} ({file_size_mb:.2f} MB)"
            )
            self.logger.info(f"Output directory: {output_dir}")
            self.logger.info(f"Using chunk size of {chunksize} rows")

            chunk_paths = []
            total_rows = 0
            file_count = 0

            parquet_file_obj = pq.ParquetFile(parquet_file)

            for i, batch in enumerate(
                parquet_file_obj.iter_batches(batch_size=chunksize)
            ):
                file_count += 1
                chunk_df = batch.to_pandas()
                rows = len(chunk_df)
                total_rows += rows

                # Create chunk filename - simple integer naming
                chunk_path = os.path.join(output_dir, f"{file_count}.csv")
                chunk_df.to_csv(chunk_path, index=False)
                chunk_paths.append(chunk_path)

                self.logger.info(
                    f"Wrote chunk {file_count} with {rows} rows to {chunk_path}"
                )

            manifest = {
                "original_file": parquet_file,
                "total_rows": total_rows,
                "chunk_count": file_count,
                "chunk_paths": chunk_paths,
                "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "chunksize": chunksize,
            }

            with open(manifest_path, "w") as f:
                json.dump(manifest, f, indent=2)

            self.logger.info(
                f"Successfully processed {parquet_file} into {file_count} chunks"
            )
            self.logger.info(f"Total rows: {total_rows}")
            self.logger.info(f"Manifest file: {manifest_path}")

            return manifest
        except Exception as e:
            self.logger.error(f"Error chunking parquet file: {e}")
            return None

    def convert_parquet_to_csv(
        self,
        parquet_file: str,
        output_csv: str = None,
        use_chunking: bool = False,
        chunksize: int = 8192,
    ):
        try:
            if use_chunking:
                return self.convert_parquet_to_csv_chunked(parquet_file, chunksize)

            if not output_csv:
                output_csv = parquet_file.replace(".parquet", ".csv")

            if os.path.exists(output_csv):
                self.logger.info(
                    f"CSV file {output_csv} already exists, skipping conversion."
                )
                return output_csv

            file_size_mb = os.path.getsize(parquet_file) / (1024 * 1024)
            self.logger.info(f"Converting {parquet_file} with size {file_size_mb}MB to CSV...")

            df = pd.read_parquet(parquet_file)
            df.to_csv(output_csv, index=False)

            self.logger.info(f"Successfully converted to {output_csv}")
            return output_csv
        except Exception as e:
            self.logger.error(f"Error converting parquet to CSV: {e}")
            return None

    def stream_to_parquet_chunks(
        self,
        url: str,
        output_dir: str,
        base_name: str,
        chunksize: int = 8192,
    ):
        if self.stop_requested:
            self.logger.info("Stop requested, aborting download")
            return None
        try:
            chunk_dir = os.path.join(output_dir, base_name)
            os.makedirs(chunk_dir, exist_ok=True)
            
            manifest_path = os.path.join(chunk_dir, "manifest.json")
            if os.path.exists(manifest_path):
                self.logger.info(f"Chunks already exist for {base_name}, manifest found at {manifest_path}")
                with open(manifest_path, "r") as f:
                    return json.load(f)
            
            temp_file = os.path.join(output_dir, f"{base_name}_temp.parquet")
            
            self.logger.info(f"Streaming {url} to chunks in {chunk_dir}")
            res = requests.get(url, stream=True, verify=False)
            res.raise_for_status()
            
            total_size = int(res.headers.get("content-length", 0))
            downloaded_size = 0
            start_time = time.time()
            chunk_count = 0
            
            with open(temp_file, "wb") as f:
                for chunk in res.iter_content(chunk_size=self.chunk_size):
                    if self.stop_requested:
                        self.logger.info("Stop requested, aborting download")
                        if os.path.exists(temp_file):
                            os.remove(temp_file)
                        return None
                    
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        chunk_count += 1
                        
                        if chunk_count % 50 == 0 and total_size > 0:
                            percent = (downloaded_size / total_size) * 100
                            elapsed = time.time() - start_time
                            speed = (
                                downloaded_size / (1024 * 1024 * elapsed)
                                if elapsed > 0
                                else 0
                            )
                            self.logger.info(
                                f"Download progress: {percent:.1f}% ({downloaded_size/(1024*1024):.1f} MB of {total_size/(1024*1024):.1f} MB), {speed:.1f} MB/s"
                            )
            
            self.logger.info(f"Processing downloaded file into parquet chunks...")
            
            chunk_paths = []
            total_rows = 0
            file_count = 0
            
            try:
                parquet_file_obj = pq.ParquetFile(temp_file)
                
                for i, batch in enumerate(parquet_file_obj.iter_batches(batch_size=chunksize)):
                    if self.stop_requested:
                        break
                        
                    file_count += 1
                    chunk_df = batch.to_pandas()
                    rows = len(chunk_df)
                    total_rows += rows
                    
                    chunk_path = os.path.join(chunk_dir, f"{file_count}.parquet")
                    
                    chunk_df.to_parquet(chunk_path, index=False)
                    chunk_paths.append(chunk_path)
                    
                    self.logger.info(f"Wrote chunk {file_count} with {rows} rows to {chunk_path}")
                
                manifest = {
                    "source_url": url,
                    "total_rows": total_rows,
                    "chunk_count": file_count,
                    "chunk_paths": chunk_paths,
                    "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "chunksize": chunksize,
                }
                
                with open(manifest_path, "w") as f:
                    json.dump(manifest, f, indent=2)
                    
                self.logger.info(f"Successfully processed data into {file_count} parquet chunks")
                self.logger.info(f"Total rows: {total_rows}")
                self.logger.info(f"Manifest file: {manifest_path}")
                
                return manifest
                
            finally:
                if os.path.exists(temp_file):
                    self.logger.info(f"Removing temporary file {temp_file}")
                    os.remove(temp_file)
                    
        except Exception as e:
            self.logger.error(f"Error in stream_to_parquet_chunks: {e}")
            if 'temp_file' in locals() and os.path.exists(temp_file):
                os.remove(temp_file)
            return None

    def _download_parquet_file(
        self,
        url: str,
        file_path: str,
        convert_to_csv: bool = False,
        use_chunking: bool = False,
        chunksize: int = 8192,
    ):
        output_dir = os.path.dirname(file_path)
        base_name = os.path.basename(file_path).replace(".parquet", "")
        
        chunk_dir = os.path.join(output_dir, base_name)
        manifest_path = os.path.join(chunk_dir, "manifest.json")
        
        if os.path.exists(manifest_path):
            self.logger.info(f"Chunks already exist for {base_name}")
            if convert_to_csv and use_chunking:
                self.logger.info(f"CSV conversion requested, checking if needed")
                pass
            return
        
        if os.path.exists(file_path):
            self.logger.info(f"File {file_path} already exists, processing into chunks")
            try:
                os.makedirs(chunk_dir, exist_ok=True)
                
                file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
                self.logger.info(f"Processing {file_path} ({file_size_mb:.2f} MB) into chunks")
                
                chunk_paths = []
                total_rows = 0
                file_count = 0
                
                parquet_file_obj = pq.ParquetFile(file_path)
                
                for i, batch in enumerate(parquet_file_obj.iter_batches(batch_size=chunksize)):
                    if self.stop_requested:
                        break
                        
                    file_count += 1
                    chunk_df = batch.to_pandas()
                    rows = len(chunk_df)
                    total_rows += rows
                    
                    chunk_path = os.path.join(chunk_dir, f"{file_count}.parquet")
                    
                    chunk_df.to_parquet(chunk_path, index=False)
                    chunk_paths.append(chunk_path)
                    
                    self.logger.info(f"Wrote chunk {file_count} with {rows} rows to {chunk_path}")
                
                manifest = {
                    "original_file": file_path,
                    "total_rows": total_rows,
                    "chunk_count": file_count,
                    "chunk_paths": chunk_paths,
                    "created_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "chunksize": chunksize,
                }
                
                with open(manifest_path, "w") as f:
                    json.dump(manifest, f, indent=2)
                    
                self.logger.info(f"Successfully processed data into {file_count} parquet chunks")
                return
            except Exception as e:
                self.logger.error(f"Error chunking existing file: {e}")
        
        self.logger.info(f"Streaming {url} directly to parquet chunks")
        if use_chunking:
            self.stream_to_parquet_chunks(
                url=url,
                output_dir=output_dir,
                base_name=base_name,
                chunksize=chunksize
            )
        else:
            self.stream_to_parquet_chunks(url=url, output_dir=output_dir, base_name=base_name, chunksize=9223372036854775807)
        
        if convert_to_csv and use_chunking:
            self.convert_parquet_to_csv_chunked(
                parquet_file=file_path,
                chunksize=chunksize
            )
            pass
    
    def _fetch_open_intel_zoneFile(
        self,
        date: str = None,
        all_active: bool = True,
        max_workers: int = 10,
        sources_to_process: str = None,
        max_days_per_month: int = None,
        convert_to_csv: bool = False,
        chunking: bool = True,
        chunksize: int = 8192,
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
                            url=parquet_url,
                            file_path=f"./zoneFile/{filename}",
                            convert_to_csv=convert_to_csv,
                            use_chunking=chunking,
                            chunksize=chunksize,
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

    def run(
        self,
        accept_terms: bool = False,
        date: str = None,
        sources: str = None,
        max_days: int = None,
        convert_to_csv: bool = False,
        chunking: bool = True,
        chunksize: int = 8192,
    ):
        self.logger.info("Starting domain fetcher")
        self.logger.info(f"Is Chunking enabled: {chunking}")
        if not accept_terms:
            self.logger.error(
                "You must accept the terms of service to proceed. https://www.openintel.nl/download/terms/"
            )
            return
        paths = self._fetch_open_intel_zoneFile(
            date=date,
            all_active=True,
            max_workers=10,
            sources_to_process=sources,
            max_days_per_month=max_days,
            convert_to_csv=convert_to_csv,
            chunking=chunking,
            chunksize=chunksize,
        )


def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description="Fetch domain information from OpenINTEL"
    )

    parser.add_argument(
        "--accept-terms",
        action="store_true",
        help="Accept terms of service from https://www.openintel.nl/download/terms/",
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
    parser.add_argument(
        "--no-chunking", action="store_true", help="Disable chunking for large files"
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=8192,
        help="Chunk size for CSV conversion (default: 8192)",
    )

    args = parser.parse_args()

    worker = None
    try:
        worker = NewDomains()
        worker.run(
            accept_terms=args.accept_terms,
            date=args.date,
            sources=args.sources,
            max_days=args.max_days,
            convert_to_csv=args.csv,
            chunking=not args.no_chunking,
            chunksize=args.chunk_size,
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
