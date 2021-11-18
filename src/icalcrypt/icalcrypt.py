#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from icalendar import Calendar

def _key_from_password(password_bytes):
    hash_object = SHA256.new(data=password_bytes)
    key_bytes = hash_object.digest()#[:16] # ugh.
    return key_bytes

def _encrypt(plaintext_bytes, key_bytes):
    cipher = AES.new(key_bytes, AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext_bytes, AES.block_size))
    ciphertext_b64bytes = b64encode(ciphertext)
    return ciphertext_b64bytes

def _decrypt(ciphertext_b64bytes, key_bytes):
    try:
        ciphertext = b64decode(ciphertext_b64bytes)
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        plaintext_bytes = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext_bytes
    except (ValueError, KeyError):
        return ciphertext_b64bytes
        
def crypt_ics(ics_bytes, crypt_category, crypt_components, crypt_function, key_bytes):
    calendar = Calendar.from_ical(ics_bytes)
    for component in calendar.walk():
        if component.name == "VEVENT":
            categories = component.get('CATEGORIES')
            if (categories):
                if (isinstance(categories,list)):
                    categories = [c for cats in categories for c in cats.cats] # sometimes, there are multiple category components in one vevent → flatten
                else:
                    categories = categories.cats
                if crypt_category in map(str, categories):
                    for crypt_component in crypt_components:
                        if (crypt_component in component):
                            print("Crypt component", crypt_component)
                            # TODO: can have multiple components (e.g. attendees) → handle lists gacefully / walk all components, set their text attribute?
                            sensitive = component[crypt_component]
                            crypted = crypt_function(sensitive.encode('utf-8'), key_bytes).decode('utf-8')
                            component[crypt_component] = crypted
    return calendar.to_ical()

DEFAULT_CRYPT_CATEGORY = "Encrypt"
DEFAULT_CRYPT_COMPNENTS = ["SUMMARY", "DESCRIPTION", "LOCATION", "ATTENDEE"]

def encrypt_ics(ics_bytes, password_bytes, 
    crypt_category = DEFAULT_CRYPT_CATEGORY,
    crypt_components = DEFAULT_CRYPT_COMPNENTS
):
    key_bytes = _key_from_password(password_bytes)
    return crypt_ics(ics_bytes, crypt_category, crypt_components, _encrypt, key_bytes)

def decrypt_ics(ics_bytes, password_bytes, 
    crypt_category = DEFAULT_CRYPT_CATEGORY,
    crypt_components = DEFAULT_CRYPT_COMPNENTS
):
    key_bytes = _key_from_password(password_bytes)
    return crypt_ics(ics_bytes, crypt_category, crypt_components, _decrypt, key_bytes)

if __name__ == "__main__":
    import sys
    with open(sys.argv[1], 'rb') as f:
        password_bytes = b'secret'
        plain_ics_bytes = f.read()
        plain_ics_bytes = Calendar.from_ical(plain_ics_bytes).to_ical()
        encrypted_ics_bytes = encrypt_ics(plain_ics_bytes, password_bytes)
        if (plain_ics_bytes == encrypted_ics_bytes):
            raise RuntimeError("Encryption failed.")
        decrypted_ics_bytes = decrypt_ics(encrypted_ics_bytes, password_bytes)
        if (plain_ics_bytes == decrypted_ics_bytes):
            print("Roundtrip OK.")
        else:
            raise RuntimeError("Decryption failed.")
