import icalcrypt
from icalendar import Calendar

if __name__ == "__main__":
    import sys
    with open(sys.argv[1], 'rb') as f:
        password_bytes = b'secret'
        plain_ics_bytes = f.read()
        plain_ics_bytes = Calendar.from_ical(plain_ics_bytes).to_ical()
        encrypted_ics_bytes = icalcrypt.encrypt_ics(plain_ics_bytes, password_bytes)
        if (plain_ics_bytes == encrypted_ics_bytes):
            raise RuntimeError("Encryption failed.")
        decrypted_ics_bytes = icalcrypt.decrypt_ics(encrypted_ics_bytes, password_bytes)
        if (plain_ics_bytes == decrypted_ics_bytes):
            print("Roundtrip OK.")
        else:
            open("plain.ics",'wb').write(plain_ics_bytes)
            open("decrypted.ics",'wb').write(decrypted_ics_bytes)
            raise RuntimeError("Decryption failed.")
