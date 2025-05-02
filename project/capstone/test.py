from triton import TritonContext, ARCH, Instruction

# Triton 설정
ctx = TritonContext()
ctx.setArchitecture(ARCH.X86_64)

# Taint 대상 설정 (예: RDI 레지스터)
ctx.setTaintRegister(ctx.registers.rdi, True)

# 간단한 바이너리 실행 및 분석
binary_code = [
    (0x400000, b"\x48\x89\xd8"),  # mov rax, rbx
    (0x400003, b"\x48\x83\xc0\x04"),  # add rax, 4
]

for addr, opcode in binary_code:
    inst = Instruction(opcode)
    inst.setAddress(addr)

    # 실행 및 taint 분석
    ctx.processing(inst)

    print(f"Instruction: {inst}")
    print(f"RAX is tainted: {ctx.isTainted(ctx.registers.rax)}")

print("Analysis completed.")