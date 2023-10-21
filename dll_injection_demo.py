from ctypes import *
from ctypes import wintypes

#constants and variables
kernel32 = windll.kernel32
LPCTSTR = c_char_p
SIZE_T = c_size_t

#function definitions. OpenProcess
OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE
#VirtualAllocEx
VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID
#WriteProcessMemory
WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL
#GetModuleHandle
GetModuleHandle = kernel32.GetModuleHandleA
GetModuleHandle.argtypes = (LPCTSTR, )
GetModuleHandle.restype = wintypes.HANDLE 
#GetProcAdddress
GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (wintypes.HANDLE, LPCTSTR)
GetProcAddress.restype = wintypes.LPCVOID
#CreateRemoteThread
class _SECURITY_ATTRIBUTES(Structure):
	_fields_ = [('nLength', wintypes.DWORD),
				('lpSecurityDescriptor', wintypes.LPVOID),
				('bInheritHandle', wintypes.BOOL)]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE

#memory stuff
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x00F0000 | 0x00100000 | 0x00000FFF)

dll = b"C:\\Program Files\\Sublime Text\\hello_world.dll"
#inject into existing notepad
pid = 26288
#Open
handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid)
if not handle:
	raise WinError()

print("Handle obtained => {0:X}".format(handle))

#create remote memory
remote_memory = VirtualAllocEx(handle, False, len(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)

if not remote_memory:
	raise WinError()

print("Memory allocated => {0:X}", hex(remote_memory))

#write
write = WriteProcessMemory(handle, remote_memory, dll, len(dll) + 1, None)

if not write:
	raise WinError()

print("Bytes written => {}".format(dll))

#new thread to load dll
load_lib = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")

print("LoadLibrary address => ", hex(load_lib))

rthread = CreateRemoteThread(handle, None, 0, load_lib, remote_memory, EXECUTE_IMMEDIATELY, None)

