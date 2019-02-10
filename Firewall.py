"""
Main Firewall Class.

Intialize like this:
f = Firewall(path_to_csv_file)
and check whether the packet is accepted or not with as following:
f.accept_packet(direction, protocol, port, ip)
"""
import csv
import pprint


class Firewall:
    """Main Class Containing all Firewall methods."""

    def __init__(self, path):
        """Initialize the rules object after reading csv file."""
        rule_list = csv.reader(open(path), delimiter=',')
        self.rules = self.process_rules(rule_list)
        pp = pprint.PrettyPrinter(indent=2)  # REMOVE
        pp.pprint(self.rules)  # REMOVE

    def process_rules(self, rule_list):
        """Process the raw rules in custom rules object."""
        rules = {
            "inbound": {
                "tcp": [],
                "udp": []
            },
            "outbound": {
                "tcp": [],
                "udp": []
            }
        }
        for curr in rule_list:
            port_ip = self.format_port_ip(curr[2:])
            rules[curr[0]][curr[1]].append(port_ip)
        return rules

    def format_port_ip(self, port_ip):
        """Convert all ports and ips to ranges."""
        port, ip = port_ip
        port, ip = list(map(int,port.split("-"))), ip.split("-")
        if len(port) < 2:
            port.append(port[0])
        if len(ip) < 2:
            ip.append(ip[0])
        return [port, ip]

    def accept_packet(self, direction, protocol, port, ip_address):
        """Check whether a packet can be accepted."""
        valid_rules = self.rules[direction][protocol]
        if not valid_rules:
            return False
        for rule in valid_rules:
            # Check port
            if int(port) < rule[0][0] or rule[0][1] < int(port):
                continue
            left = self.compare_ips(rule[1][0], ip_address)
            right = self.compare_ips(rule[1][1], ip_address)
            if left == 1 or right == -1:
                continue
            return True
        return False

    def compare_ips(self, ip1, ip2):
        """Compare ips and return 1 if ip1 is greater, else -1 (0 if equal)."""
        i1, i2 = list(map(int, ip1.split("."))), list(map(int, ip2.split(".")))
        for i in range(4):
            if i1[i] > i2[i]:
                return 1
            elif i1[i] < i2[i]:
                return -1
        return 0

# f = Firewall("./test.csv")
# print(f.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
