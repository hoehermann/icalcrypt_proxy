#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from base64 import b64encode, b64decode
from icalendar import Calendar

def _key_from_password(password_bytes):
    hash_object = SHA256.new(data=password_bytes)
    key_bytes = hash_object.digest()
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

def crypt_component(component, crypt_function, key_bytes):
    crypted_bytes = crypt_function(component.encode('utf-8'), key_bytes).decode('utf-8')
    crypted_component = component.__class__(crypted_bytes)
    crypted_component.params = component.params
    return crypted_component

def crypt_components(components, crypt_function, key_bytes):
    if (isinstance(components, list)):
        components = [crypt_component(component, crypt_function, key_bytes) for component in components]
    else:
        components = crypt_component(components, crypt_function, key_bytes)
    return components

def crypt_event(event, crypt_category, sensitive_components, crypt_function, key_bytes):
    categories = event.get('CATEGORIES')
    if (categories):
        if (not isinstance(categories, list)):
            categories = [categories]
        categories = [c for cats in categories for c in cats.cats]
        if crypt_category in map(str, categories):
            for component_key in sensitive_components:
                if (component_key in event):
                    event[component_key] = crypt_components(event[component_key], crypt_function, key_bytes)
        
def crypt_ics(ics_bytes, crypt_category, sensitive_components, crypt_function, key_bytes):
    calendar = Calendar.from_ical(ics_bytes)
    for component in calendar.walk():
        if component.name == "VEVENT":
            crypt_event(component, crypt_category, sensitive_components, crypt_function, key_bytes)
    return calendar.to_ical()

DEFAULT_CRYPT_CATEGORY = "Encrypt"
DEFAULT_SENSITIVE_COMPNENTS = ["SUMMARY", "DESCRIPTION", "LOCATION", "ATTENDEE"]

def encrypt_ics(ics_bytes, password_bytes, 
    crypt_category = DEFAULT_CRYPT_CATEGORY,
    sensitive_components = DEFAULT_SENSITIVE_COMPNENTS
):
    key_bytes = _key_from_password(password_bytes)
    return crypt_ics(ics_bytes, crypt_category, sensitive_components, _encrypt, key_bytes)

def decrypt_ics(ics_bytes, password_bytes, 
    crypt_category = DEFAULT_CRYPT_CATEGORY,
    sensitive_components = DEFAULT_SENSITIVE_COMPNENTS
):
    key_bytes = _key_from_password(password_bytes)
    return crypt_ics(ics_bytes, crypt_category, sensitive_components, _decrypt, key_bytes)
