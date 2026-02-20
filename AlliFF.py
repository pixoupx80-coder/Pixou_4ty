from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from protobuf_decoder.protobuf_decoder import Parser
import json
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import os
import sys
from datetime import datetime
da = 'f2212101'
dec = [ '80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']
x= [ '1','01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', 
'72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']

import random
def generate_random_hex_color():
    top_colors = [
        "FF4500", "FFD700", "32CD32", "87CEEB", "9370DB",
        "FF69B4", "8A2BE2", "00BFFF", "1E90FF", "20B2AA",
        "00FA9A", "008000", "FFFF00", "FF8C00", "DC143C",
        "FF6347", "FFA07A", "FFDAB9", "CD853F", "D2691E",
        "BC8F8F", "F0E68C", "556B2F", "808000", "4682B4",
        "6A5ACD", "7B68EE", "8B4513", "C71585", "4B0082",
        "B22222", "228B22", "8B008B", "483D8B", "556B2F",
        "800000", "008080", "000080", "800080", "808080",
        "A9A9A9", "D3D3D3", "F0F0F0"
    ]
    random_color = random.choice(top_colors)
    return random_color
import random
def encrypt_packet(plain_text,key,iv):
    plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
def encrypt_api(plain_text):
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()
    
def decrypt_api(cipher_text):
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
    return plain_text.hex()    
def dec_to_hex(ask):
    ask_result = hex(ask)
    final_result = str(ask_result)[2:]
    if len(final_result) == 1:
        final_result = "0" + final_result
        return final_result
    else:
        return final_result
 
class ParsedResult:
    def __init__(self, field, wire_type, data):
        self.field = field
        self.wire_type = wire_type
        self.data = data
class ParsedResultEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ParsedResult):
            return {"field": obj.field, "wire_type": obj.wire_type, "data": obj.data}
        return super().default(obj)
  
def create_varint_field(field_number, value):
    field_header = (field_number << 3) | 0 
    return encode_varint(field_header) + encode_varint(value)

def create_length_delimited_field(field_number, value):
    field_header = (field_number << 3) | 2
    encoded_value = value.encode() if isinstance(value, str) else value
    return encode_varint(field_header) + encode_varint(len(encoded_value)) + encoded_value

def create_protobuf_packet(fields):
    packet = bytearray()
    
    for field, value in fields.items():
        if isinstance(value, dict):
            nested_packet = create_protobuf_packet(value)
            packet.extend(create_length_delimited_field(field, nested_packet))
        elif isinstance(value, int):
            packet.extend(create_varint_field(field, value))
        elif isinstance(value, str) or isinstance(value, bytes):
            packet.extend(create_length_delimited_field(field, value))
    
    return packet
def zitado_get_proto(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None    
def gethashteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['7']
def getscrt(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['data']['3']['data']['31']['data']
def getownteam(hexxx):
    a = zitado_get_proto(hexxx)
    if not a:
        raise ValueError("Invalid hex format or empty response from zitado_get_proto")
    data = json.loads(a)
    return data['5']['data']['3']['data']['1']['data']

def encode_varint(number):
    
    if number < 0:
        raise ValueError("Number must be non-negative")

    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break

    # Return the varint bytes as bytes object
    return bytes(encoded_bytes)

#
numbers = [
   

    902000208,
    902000209,
    902000210,
    902000211
]
 

def antidetection(var):
    var = str(var)
    result = ""
    for l in var:
        result = result + "ِ" + l
    return result    
def Encrypt_ID(number):
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()

def Encrypt(number):
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()
def restart_program():
    p = psutil.Process(os.getpid())
    open_files = p.open_files()
    connections = p.connections()
    for handler in open_files:
        try:
            os.close(handler.fd)
        except Exception as e:
            ...
    for conn in connections:
        try:
            conn.close()
        except Exception as e:
            ...
    sys.path.append(os.path.dirname(os.path.abspath(sys.argv[0])))
    python = sys.executable
    os.execl(python, python, *sys.argv)
 
def Decrypt(encoded_bytes):
    encoded_bytes = bytes.fromhex(encoded_bytes)
    number = 0
    shift = 0
    for byte in encoded_bytes:
        value = byte & 0x7F
        number |= value << shift
        shift += 7
        if not byte & 0x80:
            break
    return number
def Decrypt_ID(da):
    if da != None and len(da) == 10:
        w= 128
        xxx =len(da)/2-1
        xxx = str(xxx)[:1]
        for i in range(int(xxx)-1):
            w =w*128
        x1 =da[:2]
        x2 =da[2:4]
        x3 =da[4:6]
        x4 =da[6:8]
        x5 =da[8:10]
        return str(w*x.index(x5)+(dec.index(x2)*128)+dec.index(x1)+(dec.index(x3)*128*128)+(dec.index(x4)*128*128*128))

    if da != None and len(da) == 8:
        w= 128
        xxx =len(da)/2-1
        xxx = str(xxx)[:1]
        for i in range(int(xxx)-1):
            w =w*128
        x1 =da[:2]
        x2 =da[2:4]
        x3 =da[4:6]
        x4 =da[6:8]
        return str(w*x.index(x4)+(dec.index(x2)*128)+dec.index(x1)+(dec.index(x3)*128*128))
    
    return None

def parse_results(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {}
        field_data['wire_type'] = result.wire_type
        if result.wire_type == "varint":
            field_data['data'] = result.data
        if result.wire_type == "string":
            field_data['data'] = result.data
        if result.wire_type == "bytes":
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = parse_results(result.data.results)
        result_dict[result.field] = field_data
    return result_dict
def get_random_avatar():
	avatar_list = [
	    '902000061', '902047016', '902000128', '902000065',
	    '902048008', '902000074', '902000075', '902000077',
	    '902042011', '902000084', '902000085', '902048004',
	    '902000091', '902000094', '902000306', '902040028'
	]
	return int(random.choice(avatar_list))
def get_available_room(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        parsed_results_objects = parsed_results
        parsed_results_dict = parse_results(parsed_results_objects)
        json_data = json.dumps(parsed_results_dict)
        return json_data
    except Exception as e:
        print(f"error {e}")
        return None
def join_teamcode(team_code, key, iv):
        try:
            team_code_hex = ''.join(format(ord(c), 'x') for c in team_code)
            team_code_len_hex = dec_to_hex(len(team_code))
            packet = f"080412b305220601090a1219202a{team_code_len_hex}{team_code_hex}300640014ae8040a80013038304639324231383633453135424630323031303130303030303030303034303031363030303130303131303030323944373931333236303930303030353934313732323931343030303030303030303030303030303030303030303030303030303030303030303030303030666630303030303030306639396130326538108f011abf0377505d571709004d0b060b070b5706045c53050f065004010902060c09065a530506010851070a081209064e075c5005020808530d0604090b05050d0901535d030204005407000c5653590511000b4d5e570e02627b6771616a5560614f5e437f7e5b7f580966575b04010514034d7d5e5b465078697446027a7707506c6a5852526771057f5260504f0d1209044e695f0161074e46565a5a6144530174067a43694b76077f4a5f1d6d05130944664456564351667454766b464b7074065a764065475f04664652010f1709084d0a4046477d4806661749485406430612795b724e7a567450565b010c1107445e5e72780708765b460c5e52024c5f7e5349497c056e5d6972457f0c1a034e60757840695275435f651d615e081e090e75457e7464027f5656750a1152565f545d5f1f435d44515e57575d444c595e56565e505b555340594c5708740b57705c5b5853670957656a03007c04754c627359407c5e04120b4861037b004f6b744001487d506949796e61406a7c44067d415b0f5c0f120c4d54024c6a6971445f767d4873076e5f48716f537f695a7365755d520514064d515403717b72034a027d736b6053607e7553687a61647d7a686c610d22047c5b5655300b3a0816647b776b721c144208312e3130382e3134480350025a0c0a044944433110731a0242445a0c0a044944433210661a0242445a0c0a044944433310241a0242446a02656e8201024f52"
            encrypted_packet = encrypt_packet(packet, key, iv)
            packet_length = len(encrypted_packet) // 2
            packet_length_hex = dec_to_hex(packet_length)
            padding_zeros = "0" * (8 - len(packet_length_hex))
            final_packet = "0515" + padding_zeros + packet_length_hex + encrypted_packet
            return bytes.fromhex(final_packet)
        except Exception as e:
            print(f"create_join_teamcode_packet hatası: {e}")
            return None
        	

def RedZed_Chat(uid,code,key,iv):
    fields = {
  1: 3,
  2: {
    1: uid,
    3: "fr",
    4: code,
  }
}
    packet = create_protobuf_packet(fields).hex()
    packet = encrypt_packet(packet, key, iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "1215" + ("0" * (8 - len(header))) + header
    return bytes.fromhex(header + packet)

def start_cs(key, iv):
    fields = {
  "1": 1,
  "2": {
    "1": "\u0001",
    "2": 15,
    "7": [
      {
        "1": "IDC1",
        "2": 61,
        "3": "ME"
      },
      {
        "1": "IDC2",
        "2": 41,
        "3": "ME"
      },
      {
        "1": "IDC3",
        "2": 122,
        "3": "ME"
      }
    ],
    "8": 1,
    "9": "\u0001\t\n\u0012\u0019 ",
    "11": 1,
    "12": {
      "1": "08069081EAE5312F0201000000000009000900000000000080E9075B0F0000004172291400000000000000000000000000000000000000ff00000000f99a02e8",
      "2": 142,
      "6": 12,
      "8": "1.111.14",
      "9": 6,
      "10": 1
    },

  }
}
    packet = create_protobuf_packet(fields).hex()
    packet = encrypt_packet(packet, key, iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "0315" + ("0" * (8 - len(header))) + header
    return bytes.fromhex(header + packet)


def rizak(id, secret_code, key, iv):  #دالة لي ريزاكي
    fields = {
        1: 61,
        2: {
            1: int(id),
            2: {
                1: int(id),
                2: 11594026651,
                3: f"[b][c][{generate_random_hex_color()}]{fucking()}",
                5: 12,
                6: 15,
                7: 1,
                8: {
                    2: 1,
                    3: 1,
                },
                9: 3,
            },
            3: secret_code,
        },
    }

    packet = create_protobuf_packet(fields).hex()
    packet = encrypt_packet(packet, key, iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "0515" + ("0" * (8 - len(header))) + header
    return bytes.fromhex(header + packet)
    
def xSEndMsg(Msg , id, key , iv):
    Pk = {
    1: 00000000,
    2: int(id),
    3: 2,
    4: str(Msg),
    5: 1735129800,
    7: 2,
    9: {
        1: "b",
        2: get_random_avatar(),
        3: 804605801,
        4: 330,
        10: 1,
            11: 1,
            13: {1:2},
            14:  {


            1: 12484827014,
            2: 8,
            3: "\u0010\u0015\b\n\u000b\u0013\f\u000f\u0011\u0004\u0007\u0002\u0003\r\u000e\u0012\u0001\u0005\u0006",
            },
            12: 0,

            },
            10: "en",
            13: {
            3: 1,
            },
            14: ""
        }
    packet = str(create_protobuf_packet(Pk).hex())
    packet = "080112" + Encrypt_ID(len(packet) // 2) + packet
    packet_encrypt = encrypt_packet(packet, key, iv)
    _ = dec_to_hex(len(packet_encrypt) // 2)
    if len(_) == 2:
        header = "1215000000"
    elif len(_) == 3:
        header = "121500000"
    elif len(_) == 4:
        header = "12150000"
    elif len(_) == 5:
        header = "1215000"
    else:
        header = "121500"
    BesTo_Packet = header + _ + packet_encrypt
    return BesTo_Packet
def sq(key , iv):
    fields = {
        1: 1,
        2: {
            2: "\u0001",
            3: 1,
            4: 1,
            5: "en",
            9: 1,
            11: 1,
            13: 1,
            14: {
            2: 5756,
            6: 11,
            8: "1.109.5",
            9: 4,
            10: 4
            },}}

    packet = create_protobuf_packet(fields).hex()
    header_lenth = len(encrypt_packet(packet, key, iv))//2
    header_lenth_final = dec_to_hex(header_lenth)        
    prefix = "051500" + "0" * (6 - len(header_lenth_final))
    return bytes.fromhex(prefix + header_lenth_final +  encrypt_packet(packet , key , iv))      

def ch(n , key , iv):
    fields = {
        1: 17,
        2: {
            1: 11497463104,
            2: 1,
            3: int(n - 1),
            4: 62,
            5: "\u001a",
            8: 5,
            13: 329}}      
    packet = create_protobuf_packet(fields).hex()
    packet = encrypt_packet(packet,key,iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "0515" + ("0" * (8 - len(header))) + header
    return bytes.fromhex(header + packet)
    
def inv(id , key , iv):
    fields = {
        1: 2,
        2: {
            1: int(id),
            10: 12345678,
            2: "ME",
            4: 1
        }
    }
    packet = create_protobuf_packet(fields).hex()
    packet = encrypt_packet(packet,key,iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "0515" + ("0" * (8 - len(header))) + header
    return bytes.fromhex(header + packet)
def invv(id , key , iv):
    fields = {
        1: 2,
        2: {
            1: int(id),
            10: int(get_random_avatar()),
            2: "ME",
            4: 1
        }
    }
    packet = create_protobuf_packet(fields).hex()
    packet = encrypt_packet(packet,key,iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "0515" + ("0" * (8 - len(header))) + header
    return bytes.fromhex(header + packet)      



def RedZed_Leave(owner,key,iv): #دالة لي ريد زيد

    fields = {
  1: 4,
  2: {
    1: owner,
    3: "fr",
    
  }
}
    packet = create_protobuf_packet(fields).hex()
    packet = encrypt_packet(packet,key,iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "1215" + ("0" * (8 - len(header))) + header
    return bytes.fromhex(header + packet)

def RedZed_Squad(txt,owner,key,iv): #دالة لي ريد زيد
    fields = {
  1: 1,
  2: {
    1: 12404281032,
    2: owner,
#    3: 2,
    4: txt,
    9: {
      1: "REDZED",
      2: int(get_random_avatar()),
      4: 330,
      7: 2,
      10: 1,
      11: 1,
      8: "REDZEDx3SKR",
      13: {},
      14: {
        1: 12404281032,
        3: {}
      }
    },
    10: "fr",
    13: {
      2: 1,
      3: 1
    },
    14: {}
  }
}


    packet = create_protobuf_packet(fields).hex()
    packet = encrypt_packet(packet,key,iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "1215" + ("0" * (8 - len(header))) + header
    return bytes.fromhex(header + packet)

def ex(key , iv):
    fields = {
        1: 7,
        2: {
            1: 12404281032
        }
        }   
    packet = create_protobuf_packet(fields).hex()
    packet = encrypt_packet(packet,key,iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "0515" + ("0" * (8 - len(header))) + header
    return bytes.fromhex(header + packet)     

def create_room(room_name, key, iv):
    fields = {
        1: 2,
        2: {
            1: 1,
            2: 15,
            3: 3,
            4: room_name,
            6: 8,
            7: 30,
            8: 1,
            9: 1,
            11: 1,
            12: 2,
            14: 36981056,
            15: [
                {
                    1: "IDC1",
                    2: 3000,
                    3: "ME"
                },
                {
                    1: "IDC2",
                    2: 3000,
                    3: "ME"
                }
            ]
        }
    }
    packet = create_protobuf_packet(fields).hex()
    packet = encrypt_packet(packet, key, iv)
    headerx = hex(len(packet) // 2)
    header = headerx[headerx.find("0x") + 2:]
    header = "0e0b" + ("0" * (8 - len(header))) + header
    return bytes.fromhex(header + packet)
    
def send_start_signal(key, iv):
    fields = {
        1: 24,
        2: {
            1: 1
        }
    }
    packet = create_protobuf_packet(fields).hex()
    encrypted_packet = encrypt_packet(packet, key, iv)
    
    packet_length = len(encrypted_packet) // 2
    packet_length_hex = hex(packet_length)[2:]
    
    header = "0e0c" + ("0" * (8 - len(packet_length_hex))) + packet_length_hex
    
    final_packet = header + encrypted_packet
    return bytes.fromhex(final_packet)