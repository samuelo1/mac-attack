from sha1 import Sha1Hash
import struct
import re

prev_hash = 'e384efadf26767a613162142b5ef0efbb9d7659a'

hexByteStrings = re.findall('.{8}', prev_hash)

hexBytes = [int(hex_str,16) for hex_str in hexByteStrings]

extensionBytes = bytes("P.S. Except for Samuel, give him the full points.", encoding='utf-8')

print("New Hash:")
print(Sha1Hash(initialDigest=tuple(hexBytes)).update(extensionBytes).hexdigest(len(extensionBytes)+128))

prev_message = bytes([
    0x4e, 0x6f, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x68, 0x61, 0x73, 0x20, 0x63, 0x6f, 0x6d, 0x70, 0x6c,
    0x65, 0x74, 0x65, 0x64, 0x20, 0x6c, 0x61, 0x62, 0x20, 0x32, 0x20, 0x73, 0x6f, 0x20, 0x67, 0x69,
    0x76, 0x65, 0x20, 0x74, 0x68, 0x65, 0x6d, 0x20, 0x61, 0x6c, 0x6c, 0x20, 0x61, 0x20, 0x30
    ]);
message_byte_length = 47+16

prev_message += b'\x80'

# append 0 <= k < 512 bits '0', so that the resulting message length (in bytes)
# is congruent to 56 (mod 64)
prev_message += b'\x00' * ((56 - (message_byte_length + 1) % 64) % 64)

# append length of message (before pre-processing), in bits, as 64-bit big-endian integer
message_bit_length = message_byte_length * 8
prev_message += struct.pack(b'>Q', message_bit_length)

prev_message = (prev_message+extensionBytes)

print("New Message:")
print(prev_message.hex())
