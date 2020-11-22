# web_enumeration
Resolve list of domains and create screenshots

```
python3 web_enumeration/resolve_domains.py -i domain_info/domains.txt -o domain_info

nmap -Pn -v -n --top-ports 10000 -iL domain_info/ips.txt -oA domain_info/nmap/10000_tcp_all_ips

python3 web_enumeration/create_screenshots.py -d domain_info/domains_ips.csv -n domain_info/nmap/10000_tcp_all_ips.xml -o domain_info/format.txt -v

cat format.txt | ./aquatone -resolution "1440,900" -out web_screenshots
```
