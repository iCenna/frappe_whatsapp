"""Webhook."""
import base64

import frappe
import json
import requests
import time
from werkzeug.wrappers import Response
import frappe.utils

from frappe_whatsapp.utils import get_whatsapp_account


@frappe.whitelist(allow_guest=True)
def webhook():
    """Meta webhook."""
    if frappe.request.method == "GET":
        return get()
    return post()


def get():
    """Get."""
    hub_challenge = frappe.form_dict.get("hub.challenge")
    verify_token = frappe.form_dict.get("hub.verify_token")
    webhook_verify_token = frappe.db.get_value(
        'WhatsApp Account',
        {"webhook_verify_token": verify_token},
        'webhook_verify_token'
    )
    if not webhook_verify_token:
        frappe.throw("No matching WhatsApp account")

    if frappe.form_dict.get("hub.verify_token") != webhook_verify_token:
        frappe.throw("Verify token does not match")

    return Response(hub_challenge, status=200)


def post():
    """Post."""
    data = frappe.local.form_dict
    frappe.get_doc({
        "doctype": "WhatsApp Notification Log",
        "template": "Webhook",
        "meta_data": json.dumps(data)
    }).insert(ignore_permissions=True)

    messages = []
    phone_id = None
    try:
        messages = data["entry"][0]["changes"][0]["value"].get("messages", [])
        phone_id = data.get("entry", [{}])[0].get("changes", [{}])[0].get("value", {}).get("metadata", {}).get(
            "phone_number_id")
    except KeyError:
        messages = data["entry"]["changes"][0]["value"].get("messages", [])
    sender_profile_name = next(
        (
            contact.get("profile", {}).get("name")
            for entry in data.get("entry", [])
            for change in entry.get("changes", [])
            for contact in change.get("value", {}).get("contacts", [])
        ),
        None,
    )

    whatsapp_account = get_whatsapp_account(phone_id) if phone_id else None
    if not whatsapp_account:
        return

    if messages:
        for message in messages:
            message_type = message['type']
            is_reply = True if message.get('context') and 'forwarded' not in message.get('context') else False
            reply_to_message_id = message['context']['id'] if is_reply else None
            if message_type == 'text':
                frappe.get_doc({
                    "doctype": "WhatsApp Message",
                    "type": "Incoming",
                    "from": message['from'],
                    "message": message['text']['body'],
                    "message_id": message['id'],
                    "reply_to_message_id": reply_to_message_id,
                    "is_reply": is_reply,
                    "content_type": message_type,
                    "profile_name": sender_profile_name,
                    "whatsapp_account": whatsapp_account.name
                }).insert(ignore_permissions=True)
            elif message_type == 'reaction':
                frappe.get_doc({
                    "doctype": "WhatsApp Message",
                    "type": "Incoming",
                    "from": message['from'],
                    "message": message['reaction']['emoji'],
                    "reply_to_message_id": message['reaction']['message_id'],
                    "message_id": message['id'],
                    "content_type": "reaction",
                    "profile_name": sender_profile_name,
                    "whatsapp_account": whatsapp_account.name
                }).insert(ignore_permissions=True)
            elif message_type == 'interactive':
                interactive_data = message['interactive']
                interactive_type = interactive_data.get('type')

                # Handle button reply
                if interactive_type == 'button_reply':
                    frappe.get_doc({
                        "doctype": "WhatsApp Message",
                        "type": "Incoming",
                        "from": message['from'],
                        "message": interactive_data['button_reply']['id'],
                        "message_id": message['id'],
                        "reply_to_message_id": reply_to_message_id,
                        "is_reply": is_reply,
                        "content_type": "button",
                        "profile_name": sender_profile_name,
                        "whatsapp_account": whatsapp_account.name
                    }).insert(ignore_permissions=True)
                # Handle list reply
                elif interactive_type == 'list_reply':
                    frappe.get_doc({
                        "doctype": "WhatsApp Message",
                        "type": "Incoming",
                        "from": message['from'],
                        "message": interactive_data['list_reply']['id'],
                        "message_id": message['id'],
                        "reply_to_message_id": reply_to_message_id,
                        "is_reply": is_reply,
                        "content_type": "button",
                        "profile_name": sender_profile_name,
                        "whatsapp_account": whatsapp_account.name
                    }).insert(ignore_permissions=True)
                # Handle WhatsApp Flows (nfm_reply)
                elif interactive_type == 'nfm_reply':
                    nfm_reply = interactive_data['nfm_reply']
                    response_json_str = nfm_reply.get('response_json', '{}')

                    # Parse the response JSON
                    try:
                        flow_response = json.loads(response_json_str)
                    except json.JSONDecodeError:
                        flow_response = {}

                    # Create a summary message from the flow response
                    summary_parts = []
                    for key, value in flow_response.items():
                        if value:
                            summary_parts.append(f"{key}: {value}")
                    summary_message = ", ".join(summary_parts) if summary_parts else "Flow completed"

                    msg_doc = frappe.get_doc({
                        "doctype": "WhatsApp Message",
                        "type": "Incoming",
                        "from": message['from'],
                        "message": summary_message,
                        "message_id": message['id'],
                        "reply_to_message_id": reply_to_message_id,
                        "is_reply": is_reply,
                        "content_type": "flow",
                        "flow_response": json.dumps(flow_response),
                        "profile_name": sender_profile_name,
                        "whatsapp_account": whatsapp_account.name
                    }).insert(ignore_permissions=True)

                    # Publish realtime event for flow response
                    frappe.publish_realtime(
                        "whatsapp_flow_response",
                        {
                            "phone": message['from'],
                            "message_id": message['id'],
                            "flow_response": flow_response,
                            "whatsapp_account": whatsapp_account.name
                        }
                    )
            elif message_type in ["image", "audio", "video", "document"]:
                token = whatsapp_account.get_password("token")
                url = f"{whatsapp_account.url}/{whatsapp_account.version}/"

                media_id = message[message_type]["id"]
                headers = {
                    'Authorization': 'Bearer ' + token

                }
                response = requests.get(f'{url}{media_id}/', headers=headers)

                if response.status_code == 200:
                    media_data = response.json()
                    media_url = media_data.get("url")
                    mime_type = media_data.get("mime_type")
                    file_extension = mime_type.split('/')[1]

                    media_response = requests.get(media_url, headers=headers)
                    if media_response.status_code == 200:
                        file_data = media_response.content
                        file_name = f"{frappe.generate_hash(length=10)}.{file_extension}"

                        message_doc = frappe.get_doc({
                            "doctype": "WhatsApp Message",
                            "type": "Incoming",
                            "from": message['from'],
                            "message_id": message['id'],
                            "reply_to_message_id": reply_to_message_id,
                            "is_reply": is_reply,
                            "message": message[message_type].get("caption", ""),
                            "content_type": message_type,
                            "profile_name": sender_profile_name,
                            "whatsapp_account": whatsapp_account.name
                        }).insert(ignore_permissions=True)

                        file = frappe.get_doc(
                            {
                                "doctype": "File",
                                "file_name": file_name,
                                "attached_to_doctype": "WhatsApp Message",
                                "attached_to_name": message_doc.name,
                                "content": file_data,
                                "attached_to_field": "attach"
                            }
                        ).save(ignore_permissions=True)

                        message_doc.attach = file.file_url
                        message_doc.save()
            elif message_type == "button":
                frappe.get_doc({
                    "doctype": "WhatsApp Message",
                    "type": "Incoming",
                    "from": message['from'],
                    "message": message['button']['text'],
                    "message_id": message['id'],
                    "reply_to_message_id": reply_to_message_id,
                    "is_reply": is_reply,
                    "content_type": message_type,
                    "profile_name": sender_profile_name,
                    "whatsapp_account": whatsapp_account.name
                }).insert(ignore_permissions=True)
            else:
                frappe.get_doc({
                    "doctype": "WhatsApp Message",
                    "type": "Incoming",
                    "from": message['from'],
                    "message_id": message['id'],
                    "message": message[message_type].get(message_type),
                    "content_type": message_type,
                    "profile_name": sender_profile_name,
                    "whatsapp_account": whatsapp_account.name
                }).insert(ignore_permissions=True)

    else:
        changes = None
        try:
            changes = data["entry"][0]["changes"][0]
        except KeyError:
            changes = data["entry"]["changes"][0]
        update_status(changes)
    return


def update_status(data):
    """Update status hook."""
    if data.get("field") == "message_template_status_update":
        update_template_status(data['value'])

    elif data.get("field") == "messages":
        update_message_status(data['value'])


def update_template_status(data):
    """Update template status."""
    frappe.db.sql(
        """UPDATE `tabWhatsApp Templates`
        SET status = %(event)s
        WHERE id = %(message_template_id)s""",
        data
    )


def update_message_status(data):
    """Update message status."""
    id = data['statuses'][0]['id']
    status = data['statuses'][0]['status']
    conversation = data['statuses'][0].get('conversation', {}).get('id')
    name = frappe.db.get_value("WhatsApp Message", filters={"message_id": id})

    doc = frappe.get_doc("WhatsApp Message", name)
    doc.status = status
    if conversation:
        doc.conversation_id = conversation
    doc.save(ignore_permissions=True)


@frappe.whitelist(allow_guest=True)
def handle_flow_old(**kwargs):
    private_key = """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQImSofpWe/OQECAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECAxthCehR9AJBIIEyIE+387jOsw3
ftFfJhLBJnEA7NKLE/qaWveX48AUTerYdiapPGKuaLSA02LmwYTkOBIxMMQ4tlAK
cGmS+BzekCtEfwBYFYWYBfGMfbp1joj5muY2LDuYApvmj/503zyt3+s/dQ3wiVti
LRvY9d4tWueYTE4P5LKR1zfh0w8B5suTKHDByvpWeGo15ic9Y51vYmMnNmFb+BZq
xWdHL8KNb+0e/qPIcslb/rCL6fkR3Mkqrcgv/s/G9TAnAqS50Xay1L+vWkWGxBbS
F/mGOb4noOXFoyaYGqJUht9uCwHSFmPpwOgehjwWopwRcmpLq+GnHr3kRMivLjob
QLhsHm0HDd1iYugU0NC2CLgZoXO1ORlDeqlNAQbpj8RPySgTTV8VpgwMiVciUeQi
ZLUZchR7A4eeavapY9S5epFliGYuABQhxcqqpOeBT+hs83KU+UBFhEAOPAXNUQJC
+MWkfTr82amM7M06SnqZQKivVqVvmMXPICqkvT5xuCfBMRS0mvd2JD3And0pAMGD
IpujV+MtOKVkRxNeXipQ77YAvLLJ2L3qNHxqGc1qHet+hjV13WlpBgc1cjdxfh7y
5tJndEObzQKtfaUjtXxoqbY2yoyUE0quGA9KOLlEJAwGSxIuKrnKIP5EKtCjgEig
iY9lWxlj0dzhVkbCcTVkXQfdM79Iw2kbwVxC/ZcRlk9GALGnt7Kn5cI7MT+VVhKd
8WHPJgbiOzdKpYUCsaFeb6Agn9SVRybVFo0/Xei5DaLZmK7SPRSLrKx3V6XQ62Ol
NvEUp2/MBdWyDYnd7zVRqegAsbp2MTOoqEaudQUbBsBBdgpjXTH1ZZfG+96MwgYi
GNmfpKrL6X2Ir55EF74J04AzeqgytTcaoez3jWJ13r+kNh/MW5fWHTupuQH7G3AQ
upFIC3GhupZ2w6EQ2eNKlqh9XcVH+3/goOhPsnwq/h3bV6HuKxdCjl6fKpZh+IzX
Qh1940d94JDSZ4gYYrFfqj8PB3CXraTKl5tCJHAtxGciU+Apkr4SSzipqXS3ax5C
EBTvBnqYgc6p+SBpj4hpEmfolkQN7CMFYUrPe7DzSfAoOiIlMVWKp3M3P2s1fQy7
DYftADm90aC57F5zXjbzsQLrc43PYDHo5Ri0c1S4pryfcjQ+jzZL1LZ6ivMerrIF
4jmStrHHxBSixVRdR0bt5/4RmAhtPGCCJ9HuUrKxNEpSNu99IIaiUKkZB7bp2nXC
2+e9aSz99itSIzE4lLKz1+Ld221z+ms15vDu0Rg9apXB4wftWVsiHJCFG/6D7jIY
rDmCGInP/gBWGHnFrRsGexzsQ/+TLfIEN2NW4TYo40MxmsKqhrvHFs4YFPtmzIFE
Q7+JGRa1NHwcODgjYhsdCfxbh3bCTtZ7ub8F+jIBxYQCzbfJaj+sjGUM65Yli/np
GgDkJOkFKW9uFnToX4Iguu6oqTXoFiULX//BbSVbPpyCQNlBy4aguMhNLoZ2CPEO
XD4CKQ9jrV2quAPOfAWNtC2bZ0wWF3J5zA0n1ZLMGFChYDRLoYSQrO71YVb78O/O
blaAX/t/Rh0yr6Z/7atOWcOO8C6LBFAzE1jjhlOD0wbhJrYnnRLqb3Rd1exgJBI3
4jh1tk82JqnCIB2M+Miegg==
-----END ENCRYPTED PRIVATE KEY-----"""
    payload = kwargs

    decrypted_data, aes_key, iv = decrypt_request(payload)
    print("DECRYPTED FLOW DATA:", decrypted_data)

    response_json = handle_flow(decrypted_data)
    encrypted_response = encrypt_response(response_json, aes_key, iv)

    return Response(encrypted_response, mimetype="text/plain", status=200)
    frappe.log_error("Flow Response", str(kwargs))
    pass

# file: your_app/your_app/api/whatsapp_flow.py

import base64
import json
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.Padding import pad, unpad
import frappe

# ---------------------------- CONFIG ----------------------------
PRIVATE_KEY_TEXT = """-----BEGIN ENCRYPTED PRIVATE KEY-----
MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQImSofpWe/OQECAggA
MAwGCCqGSIb3DQIJBQAwFAYIKoZIhvcNAwcECAxthCehR9AJBIIEyIE+387jOsw3
ftFfJhLBJnEA7NKLE/qaWveX48AUTerYdiapPGKuaLSA02LmwYTkOBIxMMQ4tlAK
cGmS+BzekCtEfwBYFYWYBfGMfbp1joj5muY2LDuYApvmj/503zyt3+s/dQ3wiVti
LRvY9d4tWueYTE4P5LKR1zfh0w8B5suTKHDByvpWeGo15ic9Y51vYmMnNmFb+BZq
xWdHL8KNb+0e/qPIcslb/rCL6fkR3Mkqrcgv/s/G9TAnAqS50Xay1L+vWkWGxBbS
F/mGOb4noOXFoyaYGqJUht9uCwHSFmPpwOgehjwWopwRcmpLq+GnHr3kRMivLjob
QLhsHm0HDd1iYugU0NC2CLgZoXO1ORlDeqlNAQbpj8RPySgTTV8VpgwMiVciUeQi
ZLUZchR7A4eeavapY9S5epFliGYuABQhxcqqpOeBT+hs83KU+UBFhEAOPAXNUQJC
+MWkfTr82amM7M06SnqZQKivVqVvmMXPICqkvT5xuCfBMRS0mvd2JD3And0pAMGD
IpujV+MtOKVkRxNeXipQ77YAvLLJ2L3qNHxqGc1qHet+hjV13WlpBgc1cjdxfh7y
5tJndEObzQKtfaUjtXxoqbY2yoyUE0quGA9KOLlEJAwGSxIuKrnKIP5EKtCjgEig
iY9lWxlj0dzhVkbCcTVkXQfdM79Iw2kbwVxC/ZcRlk9GALGnt7Kn5cI7MT+VVhKd
8WHPJgbiOzdKpYUCsaFeb6Agn9SVRybVFo0/Xei5DaLZmK7SPRSLrKx3V6XQ62Ol
NvEUp2/MBdWyDYnd7zVRqegAsbp2MTOoqEaudQUbBsBBdgpjXTH1ZZfG+96MwgYi
GNmfpKrL6X2Ir55EF74J04AzeqgytTcaoez3jWJ13r+kNh/MW5fWHTupuQH7G3AQ
upFIC3GhupZ2w6EQ2eNKlqh9XcVH+3/goOhPsnwq/h3bV6HuKxdCjl6fKpZh+IzX
Qh1940d94JDSZ4gYYrFfqj8PB3CXraTKl5tCJHAtxGciU+Apkr4SSzipqXS3ax5C
EBTvBnqYgc6p+SBpj4hpEmfolkQN7CMFYUrPe7DzSfAoOiIlMVWKp3M3P2s1fQy7
DYftADm90aC57F5zXjbzsQLrc43PYDHo5Ri0c1S4pryfcjQ+jzZL1LZ6ivMerrIF
4jmStrHHxBSixVRdR0bt5/4RmAhtPGCCJ9HuUrKxNEpSNu99IIaiUKkZB7bp2nXC
2+e9aSz99itSIzE4lLKz1+Ld221z+ms15vDu0Rg9apXB4wftWVsiHJCFG/6D7jIY
rDmCGInP/gBWGHnFrRsGexzsQ/+TLfIEN2NW4TYo40MxmsKqhrvHFs4YFPtmzIFE
Q7+JGRa1NHwcODgjYhsdCfxbh3bCTtZ7ub8F+jIBxYQCzbfJaj+sjGUM65Yli/np
GgDkJOkFKW9uFnToX4Iguu6oqTXoFiULX//BbSVbPpyCQNlBy4aguMhNLoZ2CPEO
XD4CKQ9jrV2quAPOfAWNtC2bZ0wWF3J5zA0n1ZLMGFChYDRLoYSQrO71YVb78O/O
blaAX/t/Rh0yr6Z/7atOWcOO8C6LBFAzE1jjhlOD0wbhJrYnnRLqb3Rd1exgJBI3
4jh1tk82JqnCIB2M+Miegg==
-----END ENCRYPTED PRIVATE KEY-----"""

PRIVATE_KEY_PASSWORD = None

# ---------------------------- CRYPTO HELPERS ----------------------------
def load_private_key():
    """Load RSA private key from text"""
    return RSA.import_key(PRIVATE_KEY_TEXT.encode(), passphrase=PRIVATE_KEY_PASSWORD)

def decrypt_request(payload: dict):
    encrypted_flow_data = base64.b64decode(payload["encrypted_flow_data"])
    encrypted_aes_key = base64.b64decode(payload["encrypted_aes_key"])
    iv = base64.b64decode(payload["initial_vector"])

    private_key = load_private_key()
    rsa = PKCS1_OAEP.new(private_key)
    aes_key = rsa.decrypt(encrypted_aes_key)

    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_flow_data), AES.block_size)

    return json.loads(decrypted.decode()), aes_key, iv

def encrypt_response(response_json: dict, aes_key: bytes, iv: bytes):
    raw = json.dumps(response_json).encode()
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(raw, AES.block_size))
    return base64.b64encode(encrypted).decode()

# ---------------------------- FLOW LOGIC ----------------------------
def handle_flow(data: dict):
    screen = data.get("screen")
    form = data.get("data", {})

    if screen is None:
        return {"screen": "BOOK_APPOINTMENT", "data": {}}
    if screen == "BOOK_APPOINTMENT":
        return {
            "screen": "CONFIRMATION",
            "data": {
                "doctor": form.get("doctor"),
                "date": form.get("date"),
                "time": form.get("time")
            }
        }
    if screen == "CONFIRMATION":
        return {"screen": "SUCCESS", "data": {"message": "Appointment booked successfully"}}

    return {"screen": "ERROR", "data": {"message": "Invalid flow state"}}

# ---------------------------- Frappe API ----------------------------
@frappe.whitelist(allow_guest=True)
def whatsapp_flow():
    """
    Frappe endpoint for WhatsApp Flow
    POST JSON body with:
    - encrypted_flow_data
    - encrypted_aes_key
    - initial_vector
    """
    payload = frappe.local.request.json
    decrypted_data, aes_key, iv = decrypt_request(payload)

    # frappe.logger().info(f"DECRYPTED FLOW DATA: {decrypted_data}")

    response_json = handle_flow(decrypted_data)
    encrypted_response = encrypt_response(response_json, aes_key, iv)

    frappe.local.response.update({
        "status_code": 200,
        "type": "text",
        "data": encrypted_response
    })

