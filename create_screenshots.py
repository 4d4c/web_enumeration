#!/usr/bin/env python3


import argparse
import re
import xml.etree.ElementTree as ET

from lumberjack.lumberjack import Lumberjack


class FormatDomainsForScreenshots():
    WEB_PORTS = list(map(str, [*range(8000, 8010), 8443, *range(8080, 8090), *range(8880, 8890)]))


    def __init__(self, nmap_file, domain_file, output_file, verbose):
        self.nmap_file = nmap_file
        self.domain_file = domain_file
        self.output_file = output_file

        self.log = Lumberjack(False, verbose)

        self.log.info("Starting formating domains...")


    def main(self):
        all_domains = self.parse_nmap_xml()

        all_domains = list(set(all_domains))

        with open(self.output_file, "w") as output_file:
            for domain in all_domains:
                output_file.write(domain + "\n")


    def parse_nmap_xml(self):
        all_domains = []

        tree = ET.parse(self.nmap_file)
        root = tree.getroot()

        for host in root.findall("host"):
            ip = host.find("address").get('addr')

            domains = self.find_domain_by_ip(ip)
            if not domains:
                self.log.error("Couldn't find " + ip)
                domains = ip

            ports = host.find("ports").findall("port")
            self.log.info("Adding endpoints for " + ip)
            for port in ports:
                if port.find("state").get("state") == "open":
                    port_id = port.get("portid")
                    for domain in domains:
                        if port_id == "80":
                            all_domains.append("http://{}:80".format(domain))
                        elif port_id == "443":
                            all_domains.append("https://{}:443".format(domain))
                        elif port_id in self.WEB_PORTS:
                            all_domains.append("http://{}:{}".format(domain, port_id))
                            all_domains.append("https://{}:{}".format(domain, port_id))

        return all_domains


    def find_domain_by_ip(self, ip):
        found_domains = []

        with open(self.domain_file, "r") as domain_file:
            for line in domain_file:
                if ip in line.split(",")[1].split("\n")[0].split("/"):
                    found_domains.append(line.split(",")[0])

        return found_domains


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Create web page screenshots from NMAP file")
    parser.add_argument("-n", "--nmap", required=True, type=str, action="store", dest="nmap_file", help="Input .gnmap file")
    parser.add_argument("-d", "--domain", required=True, type=str, action="store", dest="domain_file", help="Input domains list file")
    parser.add_argument("-o", "--output", required=True, type=str, action="store", dest="output_file", help="Output file")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Verbose output")
    args = parser.parse_args()

    fdfs = FormatDomainsForScreenshots(args.nmap_file, args.domain_file, args.output_file, args.verbose)
    fdfs.main()
