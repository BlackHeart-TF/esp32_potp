import base64
from urllib.parse import unquote
def decode_base64(encoded_str):
    # If the string is URL-safe base64 encoded, decode
    # and add necessary padding
    adjusted_str = unquote(encoded_str) 
    
    padding_needed = len(adjusted_str) % 4
    if padding_needed:  # Add padding if necessary
        adjusted_str += '=' * (4 - padding_needed)
    
    try:
        decoded_bytes = base64.b64decode(adjusted_str)
        try:
            # Attempt to decode as UTF-8 text if possible
            return decoded_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # Return as bytes if it cannot be decoded to text
            return decoded_bytes
    except Exception as e:
        print(f"Error decoding Base64: {e}")
        return None

def encode_base32(input_bytes):
    
    # Encode these bytes in base32
    encoded_bytes = base64.b32encode(input_bytes)
    
    # Convert the base32 encoded bytes back to a string
    encoded_string = encoded_bytes.decode('utf-8')
    
    return encoded_string

urls = [
    "otpauth://totp/Example:username@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30",
    #"otpauth://totp/Iss1:user1?secret=JBSWY3DPEHPK3PXP&issuer=CompanyIssuer&algorithm=SHA1&digits=6&period=30",
    "otpauth://totp/LongCompanyNameIssuer:longusername12345@example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=LongCompanyNameIssuer&algorithm=SHA1&digits=6&period=30",
    "multi"
]

keys = [
        "CjkKCkhlbGxvId6tvu8SHEV4YW1wbGU6dXNlcm5hbWVAZXhhbXBsZS5jb20aB0V4YW1wbGUgASgBMAIQARgBIAAo6PbxNg",
        #"Ch8KBUhlbGxvEgpJc3MxOnVzZXIxGgRJc3MxIAEoATACEAEYASAAKLeVtYsE",
        "CmgKFEhlbGxvId6tvu9IZWxsbyHerb7vEjNMb25nQ29tcGFueU5hbWVJc3N1ZXI6bG9uZ3VzZXJuYW1lMTIzNDVAZXhhbXBsZS5jb20aFUxvbmdDb21wYW55TmFtZUlzc3VlciABKAEwAhABGAEgACjCu6%2Bn%2BP%2F%2F%2F%2F8B", 
        "CjkKCkhlbGxvId6tvu8SHEV4YW1wbGU6dXNlcm5hbWVAZXhhbXBsZS5jb20aB0V4YW1wbGUgASgBMAIKaAoUSGVsbG8h3q2%2B70hlbGxvId6tvu8SM0xvbmdDb21wYW55TmFtZUlzc3Vlcjpsb25ndXNlcm5hbWUxMjM0NUBleGFtcGxlLmNvbRoVTG9uZ0NvbXBhbnlOYW1lSXNzdWVyIAEoATACEAEYASAAKLue%2B8wF"
    ]

def parseExportData(data):
    if data[0] != 10:
        print(f"Invalid data. First char expected '10' (newline) got {data[0]}")
        return
    entry_len = 0
    index = 0
    more = True
    list = []
    while more:
        entry_len =  data[index+1] #seems to be length starting after key
        val = hex(data[entry_len]),hex(data[entry_len+1]),hex(data[entry_len+2]),hex(data[entry_len+3])
        iindex = index +1
        for i in range(3):
            fieldid = data[iindex+1]
            data_len = data[iindex+2]

            if fieldid == 10: #secret
                secret = data[iindex+3:iindex+3 + data_len]
            if fieldid == 0x12: #account
                account = data[iindex+3:iindex+3 + data_len].decode('utf-8')
            if fieldid == 0x1a: #issuer
                issuer = data[iindex+3:iindex+3 + data_len].decode('utf-8')
            
            iindex += data_len+2
        index += entry_len+2
        val = hex(data[index-1]),hex(data[index]),hex(data[index+1]),hex(data[index+2]),hex(data[index+3])
        if data[index] == 0x10:
            more = False
        list.append((str(account),secret,str(issuer)))
    return list

for i,key in enumerate(keys):
    url_safe_encoded_str = key
    decoded_url_safe = decode_base64(url_safe_encoded_str)
    print("otp:          ",urls[i])
    #print("Decoded:", decoded_url_safe)
    otps = parseExportData(decoded_url_safe)
    for account,secret,issuer in otps:
        print("reconstructed:", f"otpauth://totp/{account}?secret={encode_base32(secret)}$issuer={issuer}&algorithm=SHA1&digits=6&period=30")



