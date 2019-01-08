import pandas as pd
import sys

# a class to implement the firewall interface
class Firewall:

    # constructor, setting default file path to given firewall data 
    def __init__(self, file_path=sys.argv[1]):
        self.firewall_df = pd.read_csv(file_path, names = ["direction", "protocol", "port", "ip_address"])

        # splitting ranges for ports and ip_addresses into lists
        self.firewall_df['port'] = self.firewall_df['port'].apply(self.dash_split)
        self.firewall_df['ip_address'] = self.firewall_df['ip_address'].apply(self.dash_split)

    # a method to check whether a packet is accepted or not
    def accept_packet(self, direction, protocol, port, ip_address):
        eliminated_df = self.firewall_df.loc[self.firewall_df['direction'] == direction]
        if eliminated_df.empty:
            return False

        eliminated_df = eliminated_df.loc[eliminated_df['protocol'] == protocol]
        if eliminated_df.empty:
            return False
  
        eliminated_df = eliminated_df[eliminated_df.port.apply((lambda x : self.is_port_present(x, port)))]
        if eliminated_df.empty:
            return False

        ip_address_list = list(map(int, ip_address.split('.')))
        
        return self.is_ip_present(ip_address_list, eliminated_df)

    # (helper) to split on dash
    def dash_split(self, x):
        return x.split('-')
        
    # (helper) to check if a port is in range
    def is_port_present(self, x, port):
        x = list(map(int, x))
        if len(x) == 1:
            return port in x
        return port >= x[0] and port <= x[1]

    # (helper) to check if ip is in range
    def is_ip_present(self, ip_address, eliminated_df):
        for index, row in eliminated_df.iterrows():
            ip = row['ip_address']
            current_start_ip = list(map(int, ip[0].split('.')))
            if len(ip) > 1:
                current_end_ip = list(map(int, ip[1].split('.')))
            else:
                current_end_ip = current_start_ip
            if current_start_ip <= ip_address and ip_address <= current_end_ip:
                return True
        
        return False

if __name__ == "__main__":
    fw = Firewall()
    print(fw.accept_packet("inbound", "tcp", 80, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 53, "192.168.2.1"))
    print(fw.accept_packet("outbound", "tcp", 10234, "192.168.10.11"))
    print(fw.accept_packet("inbound", "tcp", 81, "192.168.1.2"))
    print(fw.accept_packet("inbound", "udp", 24, "52.12.48.92"))