# api/utils.py

import json
from datetime import datetime
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from protobuf_decoder.protobuf_decoder import Parser

# مفاتيح التشفير الثابتة AES
key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def EnC_AEs(HeX):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(bytes.fromhex(HeX), AES.block_size)).hex()

def EnC_Uid(n):
    n = int(n)
    e = []
    while n:
        e.append((n & 0x7F) | (0x80 if n > 0x7F else 0))
        n >>= 7
    return bytes(e).hex()

def Fix_PackEt(parsed_results):
    result_dict = {}
    for result in parsed_results:
        field_data = {'wire_type': result.wire_type}
        if result.wire_type in ["varint", "string", "bytes"]:
            field_data['data'] = result.data
        elif result.wire_type == 'length_delimited':
            field_data["data"] = Fix_PackEt(result.data.results)
        result_dict[result.field] = field_data
    return result_dict

def DeCode_PackEt(input_text):
    try:
        parsed_results = Parser().parse(input_text)
        return json.dumps(Fix_PackEt(parsed_results))
    except Exception as e:
        return json.dumps({"error": f"Failed to decode packet: {e}"})

def ToKen_GeneRaTe(Access_ToKen, Access_Uid):
    # --- تم تحديث بيانات PAYLOAD هنا ---
    # هذا هو الـ payload المحدث والنهائي
    base_data = '1a13323032352d31312d31312031323a30303a30302209667265656669726528013a07312e3131312e314232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520c4d544e2f537061636574656c5a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e329a012b476f6f676c657c36323566373136662d393161372d343935622d396631362d303866653964336336353333a2010d3137362e32382e3133352e3233aa01026172b201203433303632343537393364653836646134323561353263616164663231656564ba010134c2010848616e6468656c64ca010d4f6e65506c7573204135303130ea014034653739616666653331343134393031353434656161626562633437303537333866653638336139326464346335656533646233333636326232653936363466f00101ca020c4d544e2f537061636574656cd2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003b5ee02e803ff8502f003af13f803840780048c95028804b5ee0290048c95029804b5ee02b00404c80401d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f6c69622f61726de00401ea045f65363261623933353464386662356662303831646233333861636233333439317c2f646174612f6170702f636f6d2e6474732e667265656669726574682d66705843537068495636644b43376a4c2d574f7952413d3d2f626173652e61706bf00406f804018a050233329a050a32303139313139303236a80503b205094f70656e474c455332b805ff01c00504e005c466ea05093372645f7061727479f80583e4068806019006019a060134a2060134b2062211541141595f58011f53594c59584056143a5f535a525c6b5c04096e595c3b000e61'
    # ---------------------------------
    
    dT = bytes.fromhex(base_data)
    
    # استبدال القيم الديناميكية
    current_time = str(datetime.now())[:-7].encode()
    dT = dT.replace(b'2025-11-11 12:00:00', current_time) # تاريخ وهمي جديد للتأكد
    dT = dT.replace(b'4e79affe31414901544eaabebc4705738fe683a92dd4c5ee3db33662b2e9664f', Access_ToKen.encode())
    dT = dT.replace(b'4306245793de86da425a52caadf21eed', Access_Uid.encode())
    
    encoded_data = EnC_AEs(dT.hex())
    payload = bytes.fromhex(encoded_data)
    return payload, dT
