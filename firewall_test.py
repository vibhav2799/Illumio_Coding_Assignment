from firewall import *
import unittest

class TestFirewall:
    def test_true1(self):
        firewall = Firewall("test_data.csv")
        assert firewall.accept_packet("inbound", "tcp", 80, "192.168.1.2") == True
    
    def test_true2(self):
        firewall = Firewall("test_data.csv")
        assert firewall.accept_packet("outbound", "tcp", 45, "1.1.1.1") == True

    def test_false1(self):
        firewall = Firewall("test_data.csv")
        assert firewall.accept_packet("inbound", "udp", 53, "192.168.1.2") == False
    
    def test_false2(self):
        firewall = Firewall("test_data.csv")
        assert firewall.accept_packet("outbounds", "udp", 53, "192.168.1.2") == False

    def test_false3(self):
        firewall = Firewall("test_data.csv")
        assert firewall.accept_packet("inbound", "udp", 244343553, "192.168.1.2") == False

    def test_false4(self):
        firewall = Firewall("test_data.csv")
        assert firewall.accept_packet("outbound", "udp", 53, "266.168.1.2") == False