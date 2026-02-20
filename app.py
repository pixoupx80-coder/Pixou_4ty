import os
import sys
import jwt
import json
import requests
import time
import base64
import socket
import urllib3
import aiohttp
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from google.protobuf.timestamp_pb2 import Timestamp
import MajorLoginRes_pb2
from AlliFF import create_protobuf_packet, encrypt_packet, encrypt_api, create_room, send_start_signal, generate_random_hex_color, get_available_room
import logging
from cfonts import render

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(
    filename='errors.log',
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

print(render('AlliFF', colors=['white', 'red'], align='center'), '\n')

async def generate_access_token(session, uid, password):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "close",
    }
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067",
    }
    try:
        async with session.post(url, headers=headers, data=data) as response:
            if response.status == 200:
                resp_data = await response.json()
                if 'access_token' in resp_data:
                    return uid, password, resp_data['access_token'], resp_data['open_id']
                else:
                    logging.error(f"Authentication failed for {uid}: {resp_data}")
                    return None
            else:
                logging.error(f"Authentication request failed for {uid}: Status {response.status}")
                return None
    except Exception as e:
        logging.error(f"Error generating token for {uid}: {e}")
        return None

async def pre_generate_tokens(credentials):
    async with aiohttp.ClientSession() as session:
        tasks = [generate_access_token(session, uid, password) for uid, password in credentials]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [res for res in results if res is not None]

def load_credentials_from_json(file_path="accounts.json"):
    credentials = []
    if not os.path.exists(file_path):
        print(f"الملف '{file_path}' غير موجود!")
        return credentials
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            accounts_data = json.load(f)
        for account in accounts_data:
            uid = str(account.get('uid'))
            password = account.get('password')
            if uid and password:
                credentials.append((uid, password))
        print(f"تم تحميل {len(credentials)} حساب من ملف JSON")
        return credentials
    except Exception as e:
        print(f"خطأ في تحميل ملف JSON: {e}")
        logging.error(f"Error loading credentials from JSON: {e}")
        return []

def load_credentials_from_txt(file_path="accounts.txt"):
    credentials = []
    if not os.path.exists(file_path):
        print(f"الملف '{file_path}' غير موجود!")
        return credentials
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.read().splitlines()
        for line in lines:
            line = line.strip()
            if line and ':' in line and not line.startswith('#'):
                parts = line.split(':', 1)
                if len(parts) == 2:
                    uid, password = parts[0].strip(), parts[1].strip()
                    if uid and password:
                        credentials.append((uid, password))
        print(f"تم تحميل {len(credentials)} حساب من ملف TXT")
        return credentials
    except Exception as e:
        print(f"خطأ في تحميل ملف TXT: {e}")
        logging.error(f"Error loading credentials from TXT: {e}")
        return []

def load_credentials():
    all_credentials = []
    json_creds = load_credentials_from_json()
    if json_creds:
        all_credentials.extend(json_creds)
    txt_creds = load_credentials_from_txt()
    if txt_creds:
        all_credentials.extend(txt_creds)
    if not all_credentials:
        print("لم يتم العثور على حسابات في أي ملف!")
        print("يرجى إنشاء ملف accounts.json أو accounts.txt")
        print("صيغة accounts.json: [{'uid': '12345678', 'password': 'yourpass'}]")
        print("صيغة accounts.txt: 12345678:yourpass")
        sys.exit(1)
    return all_credentials

def restart_program():
    logging.info("Restarting program...")
    time.sleep(2)
    python = sys.executable
    os.execl(python, python, *sys.argv)

class FF_CLIENT:
    def __init__(self, room_name):
        self.credentials = load_credentials()
        self.tokens_list = []
        self.created_rooms = 0
        self.failed_rooms = 0
        self.room_name = room_name
        
    def connect2(self, uid, token, tok, host2, port2, key, iv):
        try:
            client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client2.connect((host2, int(port2)))
            client2.send(bytes.fromhex(tok))
            return client2
        except Exception as e:
            logging.error(f"Error in connect2 for {uid}: {e}")
            return None

    def connect(self, uid, token, tok, host, port, host2, port2, key, iv):
        client = None
        client2 = None
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((host, int(port)))
            client.send(bytes.fromhex(tok))
            data = client.recv(1024)
            if not data:
                raise Exception("No initial data received")
            client2 = self.connect2(uid, token, tok, host2, port2, key, iv)
            if client2 is None:
                raise Exception("Failed to establish secondary connection")
            time.sleep(0.2)
            colored_room_name = f"[{generate_random_hex_color()}]{self.room_name}"
            room_packet = create_room(colored_room_name, key, iv)
            client2.send(room_packet)
            time.sleep(0.1)
            start_packet = send_start_signal(key, iv)
            client2.send(start_packet)
            print(f"تم إنشاء روم '{colored_room_name}' للحساب {uid}")
            self.created_rooms += 1
            return True
        except Exception as e:
            print(f"فشل إنشاء روم للحساب {uid}: {e}")
            logging.error(f"Error in connect for {uid}: {e}")
            self.failed_rooms += 1
            return False
        finally:
            if client is not None:
                try:
                    client.close()
                except:
                    pass
            if client2 is not None:
                try:
                    client2.close()
                except:
                    pass

    def parse_my_message(self, serialized_data):
        try:
            MajorLogRes = MajorLoginRes_pb2.MajorLoginRes()
            MajorLogRes.ParseFromString(serialized_data)
            timestamp = MajorLogRes.kts
            key = MajorLogRes.ak
            iv = MajorLogRes.aiv
            BASE64_TOKEN = MajorLogRes.token
            timestamp_obj = Timestamp()
            timestamp_obj.FromNanoseconds(timestamp)
            timestamp_seconds = timestamp_obj.seconds
            timestamp_nanos = timestamp_obj.nanos
            combined_timestamp = timestamp_seconds * 1_000_000_000 + timestamp_nanos
            return combined_timestamp, key, iv, BASE64_TOKEN
        except Exception as e:
            logging.error(f"Error parsing MajorLoginRes: {e}")
            return None, None, None, None

    def GET_PAYLOAD_BY_DATA(self, JWT_TOKEN, NEW_ACCESS_TOKEN, date):
        try:
            token_payload_base64 = JWT_TOKEN.split('.')[1]
            token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
            decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
            decoded_payload = json.loads(decoded_payload)
            NEW_EXTERNAL_ID = decoded_payload['external_id']
            SIGNATURE_MD5 = decoded_payload['signature_md5']
            now = datetime.now()
            now_str = now.strftime("%Y-%m-%d %H:%M:%S")
            
            payload = bytes.fromhex("1a13323032362d30312d31342031323a31393a3032220966726565206669726528013a07312e3132302e324232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010d3137362e32382e3134352e3239aa01026172b201203931333263366662373263616363666463383132306439656332636330366238ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130d201025347ea014033646661396162396432353237306661663433326637623532383536346265396563343739306263373434613465626137303232353230373432376430633430f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e803c28302f003af13f80384078004cf92028804b5ee029004cf92029804b5ee02b00404c80403d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d49316855713474347641365f516f34432d58676165513d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d49316855713474347641365f516f34432d58676165513d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139363234b205094f70656e474c455332b805ff01c00504e005edb402ea05093372645f7061727479f2055c4b7173485438512b6c73302b4464496c2f4f617652726f7670795a596377676e51485151636d57776a476d587642514b4f4d63747870796f7054515754487653354a714d6967476b534c434c423651387839544161764d666c6a6f3d8806019006019a060134a2060134b206224006474f56540a011a5d0e115e00170d4b6e085709510a685a02586800096f000161")
            
            payload = payload.replace(b"2026-01-14 12:19:02", now_str.encode())
            payload = payload.replace(b"3dfa9ab9d25270faf4332f7b528564be9ec4790bc744a4eba70225207427d0c40", NEW_ACCESS_TOKEN.encode("UTF-8"))
            payload = payload.replace(b"9132c6fb72caccfdc8120d9ec2cc06b8", NEW_EXTERNAL_ID.encode("UTF-8"))
            payload = payload.replace(b"1ac4b80ecf0478a44203bf8fac6120f5", SIGNATURE_MD5.encode("UTF-8"))
            
            PAYLOAD = payload.hex()
            PAYLOAD = encrypt_api(PAYLOAD)
            PAYLOAD = bytes.fromhex(PAYLOAD)
            
            whisper_ip, whisper_port, online_ip, online_port = self.GET_LOGIN_DATA(JWT_TOKEN, PAYLOAD)
            return whisper_ip, whisper_port, online_ip, online_port
        except Exception as e:
            logging.error(f"Error in GET_PAYLOAD_BY_DATA: {e}")
            return None, None, None, None

    def GET_LOGIN_DATA(self, JWT_TOKEN, PAYLOAD):
        url = "https://clientbp.ggpolarbear.com/GetLoginData"
        headers = {
            'Expect': '100-continue',
            'Authorization': f'Bearer {JWT_TOKEN}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form_urlencoded',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
            'Host': 'clientbp.ggpolarbear.com',
            'Connection': 'close',
            'Accept-Encoding': 'gzip, deflate, br',
        }
        
        max_retries = 3
        attempt = 0

        while attempt < max_retries:
            try:
                response = requests.post(url, headers=headers, data=PAYLOAD, verify=False)
                response.raise_for_status()
                x = response.content.hex()
                json_result = get_available_room(x)
                parsed_data = json.loads(json_result)
                
                whisper_address = parsed_data['32']['data']
                online_address = parsed_data['14']['data']
                online_ip = online_address[:len(online_address) - 6]
                whisper_ip = whisper_address[:len(whisper_address) - 6]
                online_port = int(online_address[len(online_address) - 5:])
                whisper_port = int(whisper_address[len(whisper_address) - 5:])
                return whisper_ip, whisper_port, online_ip, online_port
            
            except requests.RequestException as e:
                logging.error(f"Request failed: {e}. Attempt {attempt + 1} of {max_retries}. Retrying...")
                attempt += 1
                time.sleep(2)

        logging.error("Failed to get login data after multiple attempts.")
        return None, None, None, None

    def guest_token(self, uid, password):
        url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 10;en;EN;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
            "client_id": "100067",
        }
        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            data = response.json()
            NEW_ACCESS_TOKEN = data['access_token']
            NEW_OPEN_ID = data['open_id']
            OLD_ACCESS_TOKEN = "3dfa9ab9d25270faf432f7b528564be9ec4790bc744a4eba70225207427d0c40"
            OLD_OPEN_ID = "9132c6fb72caccfdc8120d9ec2cc06b8"
            time.sleep(0.2)
            return self.TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
        except requests.RequestException as e:
            print(f"فشل التوثيق للحساب {uid}: {e}")
            logging.error(f"Authentication request failed for {uid}: {e}")
            return None
        
    def TOKEN_MAKER(self, OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, id):
        headers = {
            'X-Unity-Version': '2018.4.11f1',
            'ReleaseVersion': 'OB52',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-GA': 'v1 1',
            'Content-Length': '928',
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
            'Host': 'loginbp.ggpolarbear.com',
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip'
        }
        data = bytes.fromhex('1a13323032362d30312d31342031323a31393a3032220966726565206669726528013a07312e3132302e324232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010d3137362e32382e3134352e3239aa01026172b201203931333263366662373263616363666463383132306439656332636330366238ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130d201025347ea014033646661396162396432353237306661663433326637623532383536346265396563343739306263373434613465626137303232353230373432376430633430f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e803c28302f003af13f80384078004cf92028804b5ee029004cf92029804b5ee02b00404c80403d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d49316855713474347641365f516f34432d58676165513d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d49316855713474347641365f516f34432d58676165513d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139363234b205094f70656e474c455332b805ff01c00504e005edb402ea05093372645f7061727479f2055c4b7173485438512b6c73302b4464496c2f4f617652726f7670795a596377676e51485151636d57776a476d587642514b4f4d63747870796f7054515754487653354a714d6967476b534c434c423651387839544161764d666c6a6f3d8806019006019a060134a2060134b206224006474f56540a011a5d0e115e00170d4b6e085709510a685a02586800096f000161')
        data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        hex = data.hex()
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        URL = "https://loginbp.ggpolarbear.com/MajorLogin"
        try:
            RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
            RESPONSE.raise_for_status()
            combined_timestamp, key, iv, BASE64_TOKEN = self.parse_my_message(RESPONSE.content)
            if combined_timestamp is None or BASE64_TOKEN is None:
                logging.error(f"MajorLogin failed for {id}: Invalid response")
                return None
            
            second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
            BASE64_TOKEN = BASE64_TOKEN[:second_dot_index+44]
            
            ip, port, ip2, port2 = self.GET_PAYLOAD_BY_DATA(BASE64_TOKEN, NEW_ACCESS_TOKEN, 1)
            if ip is None or port is None or ip2 is None or port2 is None:
                return None
            
            return (BASE64_TOKEN, key, iv, combined_timestamp, ip, port, ip2, port2)
        except requests.RequestException as e:
            print(f"فشل MajorLogin للحساب {id}: {e}")
            logging.error(f"MajorLogin request failed for {id}: {e}")
            return None

    def dec_to_hex(self, ask):
        try:
            ask_result = hex(ask)
            final_result = str(ask_result)[2:]
            if len(final_result) == 1:
                final_result = "0" + final_result
            return final_result
        except Exception as e:
            logging.error(f"Error in dec_to_hex for {ask}: {e}")
            return "00"

    def get_tok(self):
        print("\n" + "─" * 50)
        print("جاري توليد التوكنات...")
        print("─" * 50)
        
        self.tokens_list = asyncio.run(pre_generate_tokens(self.credentials))
        if not self.tokens_list:
            print("فشل توليد أي توكن!")
            return
        
        print(f"تم توليد توكنات لـ {len(self.tokens_list)} حساب")
        
        batch_size = 5
        
        print("\n" + "─" * 50)
        print("جاري إنشاء الغرف...")
        print("─" * 50)
        
        for i in range(0, len(self.tokens_list), batch_size):
            batch = self.tokens_list[i:i + batch_size]
            with ThreadPoolExecutor(max_workers=batch_size) as executor:
                futures = []
                for uid, password, access_token, open_id in batch:
                    print(f"معالجة الحساب: {uid}")
                    result = self.guest_token(uid, password)
                    if result is None:
                        print(f"فشل الحصول على توكن للحساب {uid}")
                        self.failed_rooms += 1
                        continue
                    
                    token, key, iv, timestamp, ip, port, ip2, port2 = result
                    if token and ip and port and ip2 and port2:
                        try:
                            decoded = jwt.decode(token, options={"verify_signature": False})
                            account_id = decoded.get('account_id')
                            encoded_acc = hex(account_id)[2:]
                            hex_value = self.dec_to_hex(timestamp)
                            time_hex = hex_value
                            BASE64_TOKEN_ = token.encode().hex()
                            print(f"ID: {account_id} للحساب {uid}")
                            head = hex(len(encrypt_packet(BASE64_TOKEN_, key, iv)) // 2)[2:]
                            length = len(encoded_acc)
                            zeros = '00000000'
                            if length == 9:
                                zeros = '0000000'
                            elif length == 8:
                                zeros = '00000000'
                            elif length == 10:
                                zeros = '000000'
                            elif length == 7:
                                zeros = '000000000'
                            else:
                                print(f"طول غير متوقع لـ account_id {account_id}")
                            head = f'0115{zeros}{encoded_acc}{time_hex}00000{head}'
                            final_token = head + encrypt_packet(BASE64_TOKEN_, key, iv)
                            futures.append(executor.submit(self.connect, uid, token, final_token, ip, port, ip2, port2, key, iv))
                        except Exception as e:
                            print(f"خطأ في معالجة توكن للحساب {uid}: {e}")
                            self.failed_rooms += 1
                    else:
                        print(f"تخطي الحساب {uid} بسبب بيانات خادم غير صالحة")
                        self.failed_rooms += 1
                
                for future in futures:
                    try:
                        future.result()
                    except Exception as e:
                        print(f"فشل تنفيذ ثرياد: {e}")
                        self.failed_rooms += 1
            
            if i + batch_size < len(self.tokens_list):
                print("انتظار 2 ثانية قبل الدفعة التالية...")
                time.sleep(2)
        
        print("\n" + "═" * 50)
        print("انتهى إنشاء جميع الغرف!")
        print("═" * 50)
        print(f"الغرف الناجحة: {self.created_rooms}")
        print(f"الغرف الفاشلة: {self.failed_rooms}")
        print(f"المجموع: {self.created_rooms + self.failed_rooms}")
        print("═" * 50)

def STaRt_BoT():
    print("\n" + "═" * 50)
    print("مرحبًا بكم في بوت AlliFF")
    print("═" * 50)
    
    room_name = input("أدخل اسم الروم الذي تريد إنشاءه: ").strip()
    
    if not room_name:
        print("يجب إدخال اسم للروم!")
        return
    
    print(f"سيتم إنشاء الروم باسم: {room_name}")
    print("جاري التشغيل...")
    print("═" * 50)
    
    client = FF_CLIENT(room_name)
    client.get_tok()

if __name__ == "__main__":
    STaRt_BoT()