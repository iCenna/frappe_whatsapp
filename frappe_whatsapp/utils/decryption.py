import json

from Crypto.Hash import SHA256

import frappe
from werkzeug.wrappers import Response

@frappe.whitelist(allow_guest=True)
def whatsapp_flow_endpoint(**kwargs):
    import base64
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP, AES

    # 1. Parse request body JSON
    body = frappe.local.form_dict

    # 2. Base64 decode fields
    enc_aes_key = base64.b64decode(body.get("encrypted_aes_key"))
    enc_flow_data = base64.b64decode(body.get("encrypted_flow_data"))
    iv = base64.b64decode(body.get("initial_vector"))

    # 3. Load private RSA key from file
    with open("/home/dcode-frappe/private.pem", "rb") as f:
        private_key = RSA.import_key(f.read(), passphrase="203799")

    # 4. RSA decrypt AES key
    rsa_cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    aes_key = rsa_cipher.decrypt(enc_aes_key)

    # 5. AES‑GCM decrypt request
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, iv)
    decrypted = aes_cipher.decrypt_and_verify(enc_flow_data[:-16], enc_flow_data[-16:])
    req_json = json.loads(decrypted.decode("utf‑8"))

    # 6. Process Flow
    result_json = {"screen": "...", "data": {"foo": "bar"}}

    # 7. Encrypt response with inverted IV
    inv_iv = bytes(~b & 0xFF for b in iv)
    aes_enc = AES.new(aes_key, AES.MODE_GCM, inv_iv)
    ciphertext, tag = aes_enc.encrypt_and_digest(json.dumps(result_json).encode("utf‑8"))

    encrypted_response = base64.b64encode(ciphertext + tag).decode("utf‑8")
    return Response("encrypted_response", status=200)
    # return encrypted_response
