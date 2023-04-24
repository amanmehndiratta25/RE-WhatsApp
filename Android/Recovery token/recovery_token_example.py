import re
import base64
import hashlib
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
import urllib.parse

class WhatsAppSecurity:

    RECOVERY_TOKEN_HEADER = b"\x00\x02"

    def __init__(self, phone_number, google_play_email = ""):
        self.pn = phone_number
        self.email = google_play_email

    def get_recovery_token(self, rc_data):
        secret = WhatsAppData().get_rc_secret() + self.get_recovery_jid_from_jid(self.pn) + self.email;
        return self.get_encrypted_data(secret, rc_data)

    def get_rc_file_data(self, recovery_token_file):
        with open(recovery_token_file, 'rb') as f:
            read_data = f.read()
        return read_data

    def get_encrypted_data(self, secret, data):
        data = data[27:]
        header = data[:2]
        salt = data[2:6]
        iv = data[6:22]
        encrypted_data = data[22:42]

        if header != self.RECOVERY_TOKEN_HEADER:
            raise Exception('Header mismatch')

        key = self.get_key(secret, salt)
        cipher = AES.new(key, AES.MODE_OFB, iv)

        return cipher.decrypt(encrypted_data)

    def get_key(self, secret, salt):
        return hashlib.pbkdf2_hmac('sha1', bytes(secret, 'utf-8'), salt, 16, 16)

    def get_recovery_jid_from_jid(self, phone_number):
        c = re.compile("^([17]|2[07]|3[0123469]|4[013456789]|5[12345678]|6[0123456]|8[1246]|9[0123458]|\d{3})\d*?(\d{4,6})$")
        g = c.match(phone_number)

        if g is not None:
            return g.group(1) + g.group(2)
        else:
            return ""

class WhatsAppData:

    def __init__(self):
        self.RC_SECRET = self.decode("A\u0004\u001d@\u0011\u0018V\u0091\u0002\u0090\u0088\u009f\u009eT(3{;ES")

    def decode(self, s):
        sb = []
        for i in range(len(s)):
            sb.append(self.sxor("\u0012", s[i]))
        return ''.join(sb)


    def sxor(self, s1, s2):
        # convert strings to a list of character pair tuples
        # go through each tuple, converting them to ASCII code (ord)
        # perform exclusive or on the ASCII code
        # then convert the result back to ASCII (chr)
        # merge the resulting array of characters as a string
        return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

    def get_rc_secret(self):
        return self.RC_SECRET


phone_number = '34123456789' # country_code + number
account_name = '' # Google Play Email. If not set, don't change this value.

ws = WhatsAppSecurity(phone_number, '')
rc_data = ws.get_rc_file_data('rc2') # Opening and reading rc2 file data

recovery_token = ws.get_recovery_token(rc_data)

print(urllib.parse.quote_plus(recovery_token))
