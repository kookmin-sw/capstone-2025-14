# -*- coding: utf-8 -*-
from ghidra.program.model.symbol import *
from ghidra.program.model.data import *
import struct
import csv
import os

symbol_table = currentProgram.getSymbolTable()
symbols = symbol_table.getAllSymbols(True)

skip_prefixes = [
    "__DT_", "_GLOBAL_", "__init_", "__frame_", "__do_", "__JCR", "_DYNAMIC",
    "PTR_", "__GNU_", "__libc_", "__stack_chk", "_fp_", "__gmon_", "__bss_start", "_IO_",
    "__fini_", "__data_start", "__TMC_", "__start_", "__stop_", "__cxa_", "Elf32_", "fde_", "cie_",
    "NoteAbiTag", "GnuBuildId", "__FRAME_END__", "s_", "stdin", "stdout", "stderr"
]

# CSV 저장 경로: 현재 작업 디렉토리 기준
output_path = os.path.join(os.getcwd(), "global_variables.csv")
csv_file = open(output_path, "w")
csv_writer = csv.writer(csv_file)
csv_writer.writerow(["name", "address", "type", "size"])

for symbol in symbols:
    name = symbol.getName()
    addr = symbol.getAddress()

    if symbol.getSymbolType() != SymbolType.LABEL:
        continue
    if any(name.startswith(prefix) for prefix in skip_prefixes):
        continue
    if "::" in name or name.startswith(".") or addr.toString().startswith("."):
        continue

    data = getDataAt(addr)
    if not data:
        continue

    dtype = data.getDataType()
    size = data.getLength()
    typename = dtype.getDisplayName()

    # 자동 포인터 배열 추론
    if typename.startswith("undefined1[") and size % 4 == 0:
        try:
            mem = getBytes(addr, size)
            ptr_candidates = 0
            for i in range(0, size, 4):
                val = struct.unpack("<I", mem[i:i+4])[0]
                if currentProgram.getMemory().contains(toAddr(val)):
                    ptr_candidates += 1
            if ptr_candidates >= (size // 4) // 2:
                ptr = PointerDataType(CharDataType())
                element_size = ptr.getLength()
                ptr_array = ArrayDataType(ptr, size // element_size, element_size)
                clearListing(addr)
                createData(addr, ptr_array)
                dtype = ptr_array
                typename = dtype.getDisplayName()
        except:
            pass

    # 출력 및 CSV 저장
    print("[*] {} @ {} | Type: {} | Size: {}".format(name, addr, typename, size))
    csv_writer.writerow([name, "0x{}".format(addr), typename, size])

csv_file.close()
print("[+] CSV save success: {}".format(output_path))
