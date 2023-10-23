import tkinter as tk
from tkinter import scrolledtext
from tkinter import font
from scapy.all import *
import threading
import socket

class PacketCaptureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Capture GUI")

    
        self.root.configure(bg="black")

        self.is_capturing = False
        self.packet_count = 0
        self.capture_thread = None 
        self.stop_capture_flag = threading.Event()

        
        self.blocked_list = self.load_blocked_list("block_list.txt")

        
        button_frame = tk.Frame(root, bg="black")
        button_frame.pack(side="top", anchor="n")

        
        button_font = font.Font(family="Helvetica", size=16, weight="bold")
        self.capture_button = tk.Button(button_frame, text="Start Capture", command=self.toggle_capture, bg="black", fg="green", font=button_font, width=15)
        self.capture_button.pack(side="left", padx=10)  

        self.stop_button = tk.Button(button_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED, bg="black", fg="green", font=button_font, width=15)
        self.stop_button.pack(side="left", padx=10)  

    
        self.text_widget = scrolledtext.ScrolledText(root, height=10, width=50, bg="black", fg="green", font=("Helvetica", 14))
        self.text_widget.pack(expand=True, fill="both")  

    def packet_handler(self, packet):
        if packet.haslayer(IP):
            self.packet_count += 1
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            try:
                src_name = socket.gethostbyaddr(src_ip)[0]
            except socket.herror:
                src_name = "Unknown"
            try:
                dst_name = socket.gethostbyaddr(dst_ip)[0]
            except socket.herror:
                dst_name = "Unknown"

            
            protocol_type = "Unknown"
            if packet.haslayer(TCP):
                protocol_type = "TCP"
            elif packet.haslayer(UDP):
                protocol_type = "UDP"
            elif packet.haslayer(ICMP):
                protocol_type = "ICMP"
            elif packet.haslayer(HTTP):
                protocol_type = "HTTP"
                
                if (src_ip, protocol_type) in self.blocked_list or (dst_ip, protocol_type) in self.blocked_list:
                    message = f"BLOCKED - Packet {self.packet_count} - Source: {src_ip} ({src_name}) -> Destination: {dst_ip} ({dst_name}) - Protocol: {protocol_type}"
                    self.text_widget.insert(tk.END, message + "\n", "blocked")
                else:
                    message = f"Packet {self.packet_count} - Source: {src_ip} ({src_name}) -> Destination: {dst_ip} ({dst_name}) - Protocol: {protocol_type}"
                    self.text_widget.insert(tk.END, message + "\n")
            elif packet.haslayer(HTTPS):
                protocol_type = "HTTPS"

            if protocol_type != "HTTP":
                message = f"Packet {self.packet_count} - Source: {src_ip} ({src_name}) -> Destination: {dst_ip} ({dst_name}) - Protocol: {protocol_type}"
                self.text_widget.insert(tk.END, message + "\n")
            self.text_widget.see(tk.END)

    def load_blocked_list(self, file_name):
        blocked_list = set()
        try:
            with open(file_name, "r") as file:
                for line in file:
                    parts = line.strip().split()
                    if len(parts) == 2:
                        ip, protocol = parts
                        blocked_list.add((ip, protocol))
        except FileNotFoundError:
            pass
        return blocked_list

    def toggle_capture(self):
        if not self.is_capturing:
            self.start_capture()
        else:
            self.stop_capture()

    def start_capture(self):
        if not self.is_capturing:
            self.is_capturing = True
            self.capture_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.text_widget.delete(1.0, tk.END)  
            self.packet_count = 0  

            
            self.capture_thread = threading.Thread(target=self.capture_packets)
            self.capture_thread.start()

    def stop_capture(self):
        if self.is_capturing:
            self.is_capturing = False
            self.stop_capture_flag.set()  
            self.capture_thread.join()  
            self.capture_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.capture_thread = None  
            self.stop_capture_flag.clear()  

    def capture_packets(self):
        while self.is_capturing:
            if self.stop_capture_flag.is_set():  
                break
            sniff(filter="ip", prn=self.packet_handler, store=False)

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketCaptureGUI(root)
    
    
    app.text_widget.tag_configure("blocked", foreground="red")

    root.state("zoomed")  
    root.mainloop()
