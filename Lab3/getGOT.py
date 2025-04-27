from pwn import *
elf = ELF('./gotoku')
print("void *got_table[1200] = {")
for i in range(1200):
   print(f'\t(void*){elf.got["gop_" + str(i + 1)]},')
   
print("};")