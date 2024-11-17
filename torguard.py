import json
import csv
from io import BytesIO
from zipfile import ZipFile
from urllib.request import urlopen
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass

@dataclass
class Config:
    DNS_FILE: str = "dns.json"
    URL: str = "https://updates.torguard.biz/prod/Config/default.zip"
    OUTPUT_FILE: str = "torguard-ips.csv"

class IPRecord:
    def __init__(self, domain: str, first_seen: str, last_seen: str):
        self.domain = domain
        self.first_seen = first_seen
        self.last_seen = last_seen

class TorGuardIPManager:
    def __init__(self, config: Config):
        self.config = config
        self.existing_ips = {}

    def json_flip_to_list(self, old_json: Dict) -> List[Dict[str, str]]:
        return [
            {"ip_address": val, "domain": key}
            for key in old_json
            for val in old_json[key]
        ]

    def download_vpn_servers(self) -> List[Dict[str, str]]:
        with urlopen(self.config.URL) as zip_file:
            archive = ZipFile(BytesIO(zip_file.read()))
            my_json = archive.read(self.config.DNS_FILE).decode("utf8")
            json_data = json.loads(my_json)
            return self.json_flip_to_list(json_data["resolve"])

    def read_existing_ips(self) -> None:
        self.existing_ips = defaultdict(
            lambda: {"first_seen": None, "last_seen": None, "domain": None}
        )
        try:
            with open(self.config.OUTPUT_FILE, mode='r', newline='') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    self.existing_ips[row["ip_address"]] = {
                        "first_seen": row["first_seen"],
                        "last_seen": row["last_seen"],
                        "domain": row["domain"]
                    }
        except FileNotFoundError:
            pass

    def write_ips_to_csv(self) -> None:
        fieldnames = ["ip_address", "domain", "first_seen", "last_seen"]
        with open(self.config.OUTPUT_FILE, mode='w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for ip, data in self.existing_ips.items():
                writer.writerow({
                    "ip_address": ip,
                    "domain": data["domain"],
                    "first_seen": data["first_seen"],
                    "last_seen": data["last_seen"]
                })

    def update_ip_records(self, new_ips: List[Dict[str, str]]) -> None:
        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        for entry in new_ips:
            ip = entry["ip_address"]
            domain = entry["domain"]
            if ip in self.existing_ips:
                self.existing_ips[ip]["last_seen"] = current_date
            else:
                self.existing_ips[ip] = {
                    "domain": domain,
                    "first_seen": current_date,
                    "last_seen": current_date
                }

    def process(self) -> None:
        new_ips = self.download_vpn_servers()
        self.read_existing_ips()
        self.update_ip_records(new_ips)
        self.write_ips_to_csv()

def main():
    config = Config()
    manager = TorGuardIPManager(config)
    manager.process()

if __name__ == "__main__":
    main()
