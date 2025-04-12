import struct, sys, os, time, argparse, signal, subprocess
from scapy.all import *
from scapy.layers.bluetooth import ATT_Write_Request, ATT_Write_Command
from colorama import Fore, Style, init

init(autoreset=True)

# --- Banner ---
def print_banner():
    print(Fore.CYAN + Style.BRIGHT + """
 █░█ ▄▀█ █▄░█ █▀▄ █░░ █▀▀ ▀█▀ ▄▀█ █▀▀ ▀█▀
 █▀█ █▀█ █░▀█ █▄▀ █▄▄ ██▄ ░█░ █▀█ █▄▄ ░█░
 BLE REPLAY TOOL · by @souravbaghz
    """)

# --- Graceful Ctrl+C Exit ---
def handle_exit(sig, frame):
    print(Fore.YELLOW + "\n[+] Exiting cleanly.")
    sys.exit(0)

signal.signal(signal.SIGINT, handle_exit)

# --- BLE Packet Parsers ---
def parse_bt_snoop_log(file_path):
    write_ops, seq = [], 1
    with open(file_path, 'rb') as f:
        if not f.read(16).startswith(b'btsnoop'):
            raise ValueError("Invalid bt_snoop.log file")
        while True:
            header = f.read(24)
            if len(header) < 24: break
            _, inc_len, _, _, _ = struct.unpack('>IIIIq', header)
            pkt = f.read(inc_len)
            if len(pkt) < 9: continue
            if pkt[0] not in [0x02, 0x03]: continue
            data = pkt[9:]
            if len(data) < 3: continue
            op, handle = data[0], struct.unpack('<H', data[1:3])[0]
            value = data[3:]
            if op == 0x12:
                write_ops.append({'seq': seq, 'handle': handle, 'value': value, 'type': 'req'})
                seq += 1
            elif op == 0x52:
                write_ops.append({'seq': seq, 'handle': handle, 'value': value, 'type': 'cmd'})
                seq += 1
    return write_ops

def parse_pcap_ble_writes(file_path):
    packets = rdpcap(file_path)
    write_ops, seq = [], 1
    for pkt in packets:
        if pkt.haslayer(ATT_Write_Request):
            att = pkt[ATT_Write_Request]
            write_ops.append({'seq': seq, 'handle': att.gatt_handle, 'value': att.data, 'type': 'req'})
            seq += 1
        elif pkt.haslayer(ATT_Write_Command):
            att = pkt[ATT_Write_Command]
            write_ops.append({'seq': seq, 'handle': att.gatt_handle, 'value': att.data, 'type': 'cmd'})
            seq += 1
    return write_ops

def detect_file_type_and_parse(file_path):
    with open(file_path, 'rb') as f:
        return parse_bt_snoop_log(file_path) if f.read(8).startswith(b'btsnoop') else parse_pcap_ble_writes(file_path)

# --- Write Logic using gatttool ---
def send_write_gatttool(mac, handle, value_bytes, op_type):
    handle_hex = f"0x{handle:04X}"
    value_hex = value_bytes.hex()
    base_cmd = ["gatttool", "-b", mac]
    if op_type == 'req':
        base_cmd += ["--char-write-req", "-a", handle_hex, "-n", value_hex]
    else:
        base_cmd += ["--char-write", "-a", handle_hex, "-n", value_hex]
    try:
        subprocess.run(base_cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        print(Fore.RED + f"[!] gatttool failed for handle {handle_hex}")
        return False
    except FileNotFoundError:
        print(Fore.RED + "[!] gatttool not found. Please install bluez tools.")
        return False

def replay_operations(mac, ops, delay):
    for op in ops:
        print(Fore.GREEN + f"[{op['seq']}] Writing to 0x{op['handle']:04X}: {op['value'].hex().upper()} ({op['type']})")
        success = send_write_gatttool(mac, op['handle'], op['value'], op['type'])
        if not success:
            print(Fore.RED + f"[!] Failed to send seq {op['seq']}")
        time.sleep(delay)

# --- CLI Main ---
parser = argparse.ArgumentParser(description="BLE Replay using gatttool (no persistent connection)")
parser.add_argument("file", help="Input .pcap or bt_snoop.log")
parser.add_argument("-d", "--delay", type=float, default=1.0, help="Delay between writes (default: 1s)")
args = parser.parse_args()

if not os.path.exists(args.file): sys.exit("[-] File not found.")

print_banner()

writes = detect_file_type_and_parse(args.file)
if not writes: sys.exit("[!] No BLE write operations found.")

# Display parsed writes
print(Fore.MAGENTA + "\nSeq | Handle   | Value")
print(Fore.MAGENTA + "--- | -------- | --------------------------")
for op in writes:
    print(Fore.LIGHTWHITE_EX + f"{op['seq']:>3} | 0x{op['handle']:04X} | {op['value'].hex().upper()}")

# Get MAC from user
target_mac = input(Fore.YELLOW + "\nEnter target BLE MAC address (e.g., AA:BB:CC:DD:EE:FF): ").strip()
if not target_mac:
    sys.exit("[!] Target MAC is required.")

# Main interaction loop
while True:
    print(Fore.CYAN + "\nWhat do you want to do?")
    print("1. Replay all")
    print("2. Replay a range")
    print("3. Replay one")
    print("4. Loop replay")
    print("5. Exit")
    try:
        choice = input(Fore.YELLOW + "Choose (1-5): ").strip()
        if choice == "1":
            replay_operations(target_mac, writes, args.delay)

        elif choice == "2":
            s, e = map(int, input("Enter range (e.g. 3-6): ").strip().split('-'))
            subset = [op for op in writes if s <= op['seq'] <= e]
            replay_operations(target_mac, subset, args.delay)

        elif choice == "3":
            seq = int(input("Enter sequence #: "))
            subset = [op for op in writes if op['seq'] == seq]
            replay_operations(target_mac, subset, args.delay)

        elif choice == "4":
            loop_opt = input("Loop what? (1=All, 2=Range, 3=One): ").strip()
            if loop_opt == "1":
                while True:
                    replay_operations(target_mac, writes, args.delay)
            elif loop_opt == "2":
                s, e = map(int, input("Enter range (e.g. 3-6): ").strip().split('-'))
                subset = [op for op in writes if s <= op['seq'] <= e]
                while True:
                    replay_operations(target_mac, subset, args.delay)
            elif loop_opt == "3":
                seq = int(input("Enter sequence #: "))
                subset = [op for op in writes if op['seq'] == seq]
                while True:
                    replay_operations(target_mac, subset, args.delay)

        elif choice == "5":
            print(Fore.CYAN + "[*] Exiting.")
            break
        else:
            print(Fore.RED + "[!] Invalid option.")
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[+] Interrupted by user. Exiting.")
        break

