infile = "dec.txt"
outfile = "new.txt"

key = b"daubuoi"  # ASCII, không phải hex

with open(infile, "rb") as f:
    data = f.read()

key_full = (key * ((len(data) // len(key)) + 1))[:len(data)]
decoded = bytes([b ^ k for b, k in zip(data, key_full)])

with open(outfile, "wb") as f:
    f.write(decoded)

print("✅ Giải mã xong -> dec.txt")
