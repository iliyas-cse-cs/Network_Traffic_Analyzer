import tkinter as tk
from tkinter import ttk
import threading
import scapy.all as scapy

class NetworkSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Sniffer")
        self.root.geometry("400x300")

        self.interface_label = ttk.Label(root, text="Select Interface:")
        self.interface_label.pack(pady=10)

        self.interface_combobox = ttk.Combobox(root, values=self.get_available_interfaces())
        self.interface_combobox.pack(pady=10)

        self.start_button = ttk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

        self.output_text = tk.Text(root, height=10, width=40)
        self.output_text.pack(pady=10)

    def get_available_interfaces(self):
        interfaces = scapy.get_windows_if_list()
        ifaces = []
        for interface in interfaces:
            if isinstance(interface, list):
                description = interface[0]
            else:
                description = interface['description']
            ifaces.append(f"{interface}: {description}")
        return ifaces

    def start_sniffing(self):
        interface = self.interface_combobox.get().split(":")[0].strip()
        if not interface:
            messagebox.showwarning("Error", "Please select an interface.")
            return

        threading.Thread(target=self.sniff_packets, args=(interface,), daemon=True).start()

    def sniff_packets(self, interface):
        scapy.sniff(iface=interface, store=False, prn=self.process_packet, lfilter=lambda x: x.haslayer(scapy.IP))

    def process_packet(self, packet):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        if packet.haslayer(scapy.TCP):
            src_port = packet[scapy.TCP].sport
            dst_port = packet[scapy.TCP].dport
            port_info = f", Ports: {src_port} -> {dst_port}"
        else:
            port_info = ""

        packet_info = f"IP Packet on {packet.sniffed_on}: {src_ip} -> {dst_ip}, Protocol: {protocol}{port_info}\n"

        self.root.after(0, self.update_output, packet_info)

    def update_output(self, packet_info):
        self.output_text.insert(tk.END, packet_info)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkSnifferApp(root)
    root.mainloop()
