# Simple script to find was ascii values with xor with 0xeb to output bad chars

flag = 'flag.txt'

# If you wanted to use the string flag.txt
for x in range(0x00, 0x100):
    for l in flag:
        xor = chr(0b11101011 ^ x)
        if xor == l:
            print(xor, " = " , hex(x))

# If you want use some random characters so no bad characters were ever actually
#   changed.
'''
string = AAAAAAAA
for x in range(0x00, 0x100):
    for y in range(0x00, 0x100):
        xor = chr(x ^ y)
        for l in string:
            if xor == l:
                print(hex(x), " ^ ", hex(y), " = ", xor)
'''
