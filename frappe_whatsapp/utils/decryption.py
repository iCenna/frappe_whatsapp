import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
import frappe
from frappe import _

@frappe.whitelist(allow_guest=True)
def whatsapp_flow_endpoint(**kwargs):
    try:
        # 1. Get request data
        body = frappe.local.form_dict

        enc_aes_key = base64.b64decode(body.get("encrypted_aes_key"))
        enc_flow_data = base64.b64decode(body.get("encrypted_flow_data"))
        iv = base64.b64decode(body.get("initial_vector"))

        # 2. Load private key
        with open("/home/dcode-frappe/private.pem", "rb") as f:
            private_key = RSA.import_key(f.read(), passphrase="203799")

        # 3. RSA decrypt AES key
        rsa_cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_key = rsa_cipher.decrypt(enc_aes_key)

        # 4. AES-GCM decrypt request
        aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        decrypted = aes_cipher.decrypt_and_verify(enc_flow_data[:-16], enc_flow_data[-16:])
        req_json = json.loads(decrypted.decode("utf-8"))

        # Optional: Log request
        frappe.log_error(title="WhatsApp Flow Request", message=json.dumps(req_json))

        # 5. Process your flow logic here
        response_data = {
            "screen": "example_screen",
            "data": {"foo": "bar"}
        }

        # 6. Encrypt response with inverted IV
        inv_iv = bytes(~b & 0xFF for b in iv)
        aes_enc = AES.new(aes_key, AES.MODE_GCM, nonce=inv_iv)
        ciphertext, tag = aes_enc.encrypt_and_digest(json.dumps(response_data).encode("utf-8"))

        encrypted_response = base64.b64encode(ciphertext + tag).decode("utf-8")

        # 7. Return Base64 string directly (not JSON)
        frappe.local.response["type"] = "text/plain"
        frappe.local.response["message"] = encrypted_response

    except Exception as e:
        frappe.log_error(title="WhatsApp Flow Error", message=str(e))
        frappe.local.response["type"] = "text/plain"
        frappe.local.response["message"] = ""
