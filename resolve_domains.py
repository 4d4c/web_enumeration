#!/usr/bin/env python3

import ipaddress
import os
import sys
from argparse import ArgumentParser

import dns.resolver
from lumberjack.lumberjack import Lumberjack


class ResolveDomains():
    IP_FILENAME = "ips.txt"
    DOMAIN_IP_FILENAME = "domains_ips.csv"
    UNRESOLVED_FILENAME = "unresolved.txt"


    def __init__(self, input_file, output_path, verbose):
        self.input_file = input_file
        self.output_path = output_path

        self.log = Lumberjack(False, verbose)

        if not os.path.exists(self.output_path):
            self.log.error("Folder {} not found".format(self.output_path))
            sys.exit(1)

        self.domains = {
            "resolved": {},
            "unresolved": []
        }

        self.log.info("Starting resolving domains...")


    def main(self):
        with open(self.input_file, "r") as domain_file:
            for domain in domain_file:
                self.check_domain(domain.strip())

        self.log.debug(self.domains)

        self.create_files()


    def check_domain(self, domain):
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["4.2.2.1", "8.8.8.8"]

        try:
            ips = resolver.resolve(domain, "A")
            if ips:

                self.log.info("Resolved " + domain)
                self.domains["resolved"][domain] = [ips[0].to_text()]
                self.log.debug("%s: %s" % (domain, ips[0].to_text()))
                for index, ip in enumerate(ips):
                    if index != 0:
                        self.domains["resolved"][domain] += [ip.to_text()]
                        self.log.debug("%s: %s" % (domain, ip.to_text()))
                # Remove duplicates
                self.domains["resolved"][domain] = list(set(self.domains["resolved"][domain]))
            else:
                self.domains["unresolved"] += [domain]
                self.log.warning("Could not resolve " + domain)

        except:
            self.domains["unresolved"] += [domain]
            self.log.warning("Could not resolve " + domain)


    def create_files(self):
        with open(os.path.join(self.output_path, self.IP_FILENAME), "w") as ip_file:
            all_ips = []
            for domain, ips in self.domains["resolved"].items():
                for ip in ips:
                    if ip not in all_ips:
                        all_ips += [ip]
            all_ips = sorted(all_ips, key=ipaddress.IPv4Address)
            for ip in all_ips:
                ip_file.write(ip + "\n")

        with open(os.path.join(self.output_path, self.DOMAIN_IP_FILENAME), "w") as domain_ip_file:
            for domain, ips in self.domains["resolved"].items():
                domain_ip_file.write("{},{}\n".format(domain, "/".join(ips)))

        with open(os.path.join(self.output_path, self.UNRESOLVED_FILENAME), "w") as unresolved_file:
            for domain in self.domains["unresolved"]:
                unresolved_file.write(domain + "\n")


if __name__ == "__main__":
    parser = ArgumentParser(description="Resolve list of domains")
    parser.add_argument("-i", "--input", required=True, type=str, action="store", dest="input_file", help="Input file with domains")
    parser.add_argument("-o", "--output", required=True, type=str, action="store", dest="output_path", help="Output path")
    parser.add_argument("-v", "--verbose", action="store_true", dest="verbose", help="Verbose output")
    args = parser.parse_args()

    rd = ResolveDomains(args.input_file, args.output_path, args.verbose)
    rd.main()
