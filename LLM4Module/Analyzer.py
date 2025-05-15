import subprocess
from collections import deque
import re, os, csv, string, struct
from transformers import AutoTokenizer, AutoModelForCausalLM
from elftools.elf.elffile import ELFFile
from config import *

class AssemblyAnalyzer:
    def __init__(self, file_path: str):
        self.path = file_path
        self.asm_data = None
        self.user_funcs = set()
        self.func_disassemble = dict()
        self.func_call = dict()
        self.symbols = dict()  # ← 주소(int): 심볼명(str)
        self.pie_base = None
        self.rodata_start = None
        self.rodata_end = None
        self.rodata_data = None
        
    def check_architecture(self):
        # 아키텍처 확인 함수. 32bit인지 64bit인지 검사
        with open(self.path, 'rb') as f:
            elffile = ELFFile(f)
            elf_class = elffile.elfclass
            if elf_class == 32:
                print(f"{self.path} is a 32-bit ELF binary.")
            elif elf_class == 64:
                print(f"{self.path} is a 64-bit ELF binary.")
            else:
                print(f"Unknown ELF class: {elf_class}")
            return elf_class
    
    def check_pie_and_base(self):
        # pie가 적용되어 있는지 확인. 추가로 pie가 꺼져 있으면 pie_base 값도 추출 후 저장
        with open(self.path, 'rb') as f:
            elffile = ELFFile(f)
            
            # ELF Header에서 Type 확인
            elf_type = elffile['e_type']
            
            if elf_type == 'ET_DYN':  # PIE (Position Independent Executable)
                print(f"{self.path} is PIE enabled (ET_DYN).")
                self.pie_base = 0
            elif elf_type == 'ET_EXEC':  # Non-PIE 실행 파일
                entry_point = elffile['e_entry']
                self.pie_base = entry_point & 0xfffff000  # 페이지 정렬된 베이스 주소 추정
                print(f"{self.path} is non-PIE (ET_EXEC). Base address: 0x{self.pie_base:x}")
            else:
                print(f"Unknown ELF type: {elf_type}")
                self.pie_base = None
    
    def disassemble_binary(self):
        # 입력받은 바이너리를 objdump 후 결과 데이터를 저장
        try:
            result = subprocess.check_output(
                ["objdump", "-d", self.path],
                stderr=subprocess.STDOUT,
                text=True
            )
            self.asm_data = result
            print(f"{self.path} Disassembly complete.")
        except subprocess.CalledProcessError as e:
            print(f"Error during disassembly: {e.output}")
    
    def extract_user_func(self):
        # 사용자 정의 함수 이름 추출
        defined_funcs = self._get_defined_functions()
        found_funcs = re.findall(r'<([a-zA-Z0-9_]+)>:', self.asm_data)
        
        # Filter to find user functions (not library/system functions)
        for func in found_funcs:
            if func and not func.startswith('_') and not func.startswith('__') and \
               '@@' not in func and re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', func) and \
               (func in defined_funcs or func == 'main'):
                self.user_funcs.add(func)
        print(self.user_funcs)
        
    def _get_defined_functions(self):
        # 정의된 함수 추출
        """
        Get list of defined functions using nm command
        
        Returns:
            list: List of defined function names
        """
        try:
            cmd = f"nm {self.path} | grep ' T ' | awk '{{print $3}}'"
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE)
            all_funcs = result.decode().strip().split('\n')
            defined_funcs = [
                f for f in all_funcs 
                if f and not f.startswith('_') and not f.startswith('__') and '@@' not in f
            ]
        except subprocess.CalledProcessError:
            print("정의된 함수 목록을 가져오는데 실패했습니다.")
            defined_funcs = []
        
        # Always include main if available
        if 'main' not in defined_funcs and defined_funcs != ['']:
            defined_funcs.append('main')
            
        return list(set(defined_funcs))
    
    def disassemble_func(self):
        # 함수 별로 어셈블리 명령어만 추출해서 저장
        if self.asm_data is None:
            print("Disassembly not done yet.")
            return

        text_only = self.asm_data.split("Disassembly of section .fini:")[0]

        split_blocks = re.split(r'\n([0-9a-fA-F]+) <([^>]+)>:\n', text_only)

        asm_line_pattern = re.compile(r'^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+\s+(.*)$')

        for i in range(1, len(split_blocks) - 2, 3):
            func_name = split_blocks[i+1]
            raw_code = split_blocks[i+2]
            if func_name in self.user_funcs:
                clean_lines = []

                for line in raw_code.strip().splitlines():
                    match = asm_line_pattern.match(line)
                    if match:
                        asm_instr = match.group(1).strip()
                        clean_lines.append(asm_instr)

                self.func_disassemble[func_name] = '\n'.join(clean_lines)

        print(f"Disassembled {len(self.func_disassemble)} user functions (cleaned).")

    def load_rodata(self):
        # rodata 구간 확인 후 구간 저장
        with open(self.path, 'rb') as f:
            elffile = ELFFile(f)
            for section in elffile.iter_sections():
                if section.name == '.rodata':
                    self.rodata_start = section['sh_addr']
                    self.rodata_end = section['sh_addr'] + section['sh_size']
                    self.rodata_data = section.data()
                    print(f".rodata found: start=0x{self.rodata_start:x}, size=0x{section['sh_size']:x}")
                    return
        print(".rodata section not found.")
    
    def extract_string_from_rodata(self, addr):
        # rodata에서 addr 주소에 해당하는 문자열 반환
        if self.rodata_data is None:
            return None
        offset = addr - self.rodata_start
        if offset < 0 or offset >= len(self.rodata_data):
            return None
        s = b""
        for i in range(offset, len(self.rodata_data)):
            if self.rodata_data[i] == 0:
                break
            s += bytes([self.rodata_data[i]])
        try:
            return s.decode('utf-8')
        except UnicodeDecodeError:
            return None

    def modify_func_comments_64(self):
        # 64bit 디스어셈블 코드에서 문자열 또는 심볼 주석 처리
        if not self.func_disassemble:
            print("No disassembled functions.")
            return
        if self.rodata_start is None or self.rodata_data is None:
            self.load_rodata()
        if self.pie_base is None:
            self.check_pie_and_base()
        if not hasattr(self, 'symbols') or self.symbols is None:
            self.get_symbols()

        def escape_c_string(s: str) -> str:
            s = s.replace('\\', '\\\\')
            s = s.replace('\n', '\\n')
            s = s.replace('\t', '\\t')
            s = s.replace('\r', '\\r')
            s = s.replace('"', '\\"')
            return s

        pattern = re.compile(r'#\s+([0-9a-fx]+)\s+<[^>]+>')

        for func_name, code in self.func_disassemble.items():
            def replace_comment(match):
                addr_str = match.group(1)
                addr = int(addr_str, 16)

                if self.rodata_start <= addr < self.rodata_end:
                    string_val = self.extract_string_from_rodata(addr)
                    if string_val:
                        escaped = escape_c_string(string_val)
                        return f'# "{escaped}"'

                if addr in self.symbols:
                    name, typ = self.symbols[addr]
                    tag = "(function)" if typ == "FUNC" else "(global)"
                    return f'# {name} {tag}'

                return match.group(0)

            modified_code = re.sub(pattern, replace_comment, code)
            self.func_disassemble[func_name] = modified_code

        print("Updated comments for 64-bit disassembly with symbols and rodata.")
            
    def modify_func_comments_32(self):
        # 32bit 디스어셈블 코드에서 문자열 또는 심볼 주석 처리
        if not self.func_disassemble:
            print("No disassembled functions.")
            return
        if self.rodata_start is None or self.rodata_data is None:
            self.load_rodata()
        if self.pie_base is None:
            self.check_pie_and_base()
        if not hasattr(self, 'symbols') or self.symbols is None:
            self.get_symbols()

        def escape_c_string(s: str) -> str:
            s = s.replace('\\', '\\\\')
            s = s.replace('\n', '\\n')
            s = s.replace('\t', '\\t')
            s = s.replace('\r', '\\r')
            s = s.replace('"', '\\"')
            return s

        push_pattern = re.compile(r'\bpush\s+\$0x([0-9a-fA-F]+)', re.IGNORECASE)

        for func_name, code in self.func_disassemble.items():
            def replace_push_comment(match):
                addr_str = match.group(1)
                addr = int(addr_str, 16)

                if self.rodata_start <= addr < self.rodata_end:
                    string_val = self.extract_string_from_rodata(addr)
                    if string_val:
                        escaped = escape_c_string(string_val)
                        return f'{match.group(0)}   # "{escaped}"'

                if addr in self.symbols:
                    name, typ = self.symbols[addr]
                    tag = "(function)" if typ == "FUNC" else "(global)"
                    return f'{match.group(0)}   # {name} {tag}'

                return match.group(0)

            modified_code = re.sub(push_pattern, replace_push_comment, code)
            self.func_disassemble[func_name] = modified_code

        print("Updated push comments for 32-bit disassembly with symbols and rodata.")

    def get_symbols(self):
        """ELF 심볼 테이블(.symtab)에서 주소 → (이름, 타입) 매핑"""
        with open(self.path, 'rb') as f:
            elffile = ELFFile(f)
            symtab = elffile.get_section_by_name('.symtab')
            if not symtab:
                print("No symbol table found.")
                return

            for symbol in symtab.iter_symbols():
                sym_addr = symbol['st_value']
                sym_name = symbol.name
                sym_type = symbol['st_info']['type']
                if sym_name and sym_addr != 0:
                    self.symbols[sym_addr] = (sym_name, sym_type)
        print(f"Loaded {len(self.symbols)} symbols from ELF.")
    
    def modify_func_name(self):
        # __isoc99_scanf 함수를 scanf 함수로 변경
        if not self.func_disassemble:
            print("No disassembled functions.")
            return

        for func_name, code in self.func_disassemble.items():
            modified_code = code.replace('__isoc99_scanf', 'scanf')
            self.func_disassemble[func_name] = modified_code
    
    def local_var_comments(self):
        if not self.func_disassemble:
            print("No disassembled functions.")
            return

        # 32bit, 64bit 공용 정규식
        # 예시:
        #   sub    $0x80,%esp
        #   add    $0xffffff80,%rsp
        pattern = re.compile(r'\b(sub|add)\s+\$0x([0-9a-fA-F]+),\s*%(esp|rsp)', re.IGNORECASE)

        for func_name, code in self.func_disassemble.items():
            first_local_var_found = False
            lines = code.strip().splitlines()
            modified_lines = []

            for idx, line in enumerate(lines):
                match = pattern.search(line)
                if match and not first_local_var_found and idx < 4:
                    direction, hex_value, reg = match.groups()

                    # 값 해석 (4바이트 or 8바이트 정수)
                    value = int(hex_value, 16)

                    if direction.lower() == "add":
                        # 2의 보수 처리 (64bit 고려)
                        if reg == "esp":
                            value = -((~value + 1) & 0xffffffff)
                        else:  # rsp
                            value = -((~value + 1) & 0xffffffffffffffff)

                    comment = f"{line}   # Total local variable : {abs(value)} bytes"
                    modified_lines.append(comment)
                    first_local_var_found = True
                else:
                    modified_lines.append(line)

            self.func_disassemble[func_name] = '\n'.join(modified_lines)

        print("Annotated local variable allocation in 32/64-bit function prologues.")

    def function_calls(self):
        if not self.func_disassemble:
            print("No disassembled functions.")
            return

        call_pattern = re.compile(r'\bcall\s+(?:[0-9a-fx]+)?\s*<([^@>\s]+)(?:@[^>]*)?>')

        for func_name, code in self.func_disassemble.items():
            calls = call_pattern.findall(code)
            # 중복 제거 및 정렬 (선택)
            unique_calls = sorted(set(calls))
            self.func_call[func_name] = unique_calls

        print("Extracted function calls for each user-defined function.")
    
    def disassemble64(self):
        # 64bit 바이너리일 때 실행
        self.check_pie_and_base()
        self.disassemble_binary()
        self.extract_user_func()
        self.disassemble_func()
        self.get_symbols()
        self.modify_func_comments_64()
        self.function_calls()
        self.local_var_comments()
        self.modify_func_name()
        
    def disassemble32(self):
        # 32bit 바이너리일 때 실행
        self.check_pie_and_base()
        self.disassemble_binary()
        self.extract_user_func()
        self.disassemble_func()
        self.get_symbols()
        self.modify_func_comments_32()
        self.function_calls()
        self.local_var_comments()
        self.modify_func_name()
        
    def disassemble(self):
        # 이 함수만 실행하면 자동으로 32bit, 64bit 분류 후 주석 처리된 objdump 데이터 저장
        # 최종 디스어셈블 코드는 self.func_disassemble 에 name:code 형태로 저장됨
        arch = self.check_architecture()
        if arch == 32:
            self.disassemble32()
        elif arch == 64:
            self.disassemble64()
        else:
            print("Error : Not Found Architecture!")

class GhidraAnalyzer:
    def __init__(self, file_path: str, ghidra_path: str, decompile_script: str, parse_script:str, proj_path="."):
        self.ghidra_path = ghidra_path
        self.project_path = proj_path
        self.decompile_script = decompile_script
        self.parse_script = parse_script
        self.path = file_path
        self.pie_base = 0
        self.asm_data = None
        self.ghidra_decompile = None
        self.user_funcs = set()
        self.func_decompiled = dict()
        self.global_var = dict()
        
    def check_pie_and_base(self):
        # pie가 적용되어 있는지 확인. 추가로 pie가 꺼져 있으면 pie_base 값도 추출 후 저장
        with open(self.path, 'rb') as f:
            elffile = ELFFile(f)
            
            # ELF Header에서 Type 확인
            elf_type = elffile['e_type']
            
            if elf_type == 'ET_DYN':  # PIE (Position Independent Executable)
                print(f"{self.path} is PIE enabled (ET_DYN).")
                self.pie_base = 0
            elif elf_type == 'ET_EXEC':  # Non-PIE 실행 파일
                entry_point = elffile['e_entry']
                self.pie_base = entry_point & 0xfffff000  # 페이지 정렬된 베이스 주소 추정
                print(f"{self.path} is non-PIE (ET_EXEC). Base address: 0x{self.pie_base:x}")
            else:
                print(f"Unknown ELF type: {elf_type}")
                self.pie_base = None
        
    def disassemble_binary(self):
        # 입력받은 바이너리를 objdump 후 결과 데이터를 저장
        try:
            result = subprocess.check_output(
                ["objdump", "-d", self.path],
                stderr=subprocess.STDOUT,
                text=True
            )
            self.asm_data = result
            print(f"{self.path} Disassembly complete.")
        except subprocess.CalledProcessError as e:
            print(f"Error during disassembly: {e.output}")
            
    def extract_user_func(self):
        # 사용자 정의 함수 이름 추출
        defined_funcs = self._get_defined_functions()
        found_funcs = re.findall(r'<([a-zA-Z0-9_]+)>:', self.asm_data)
        
        # Filter to find user functions (not library/system functions)
        for func in found_funcs:
            if func and not func.startswith('_') and not func.startswith('__') and \
               '@@' not in func and re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', func) and \
               (func in defined_funcs or func == 'main'):
                self.user_funcs.add(func)
        print(self.user_funcs)
        
    def _get_defined_functions(self):
        # 정의된 함수 추출
        """
        Get list of defined functions using nm command
        
        Returns:
            list: List of defined function names
        """
        try:
            cmd = f"nm {self.path} | grep ' T ' | awk '{{print $3}}'"
            result = subprocess.check_output(cmd, shell=True, stderr=subprocess.PIPE)
            all_funcs = result.decode().strip().split('\n')
            defined_funcs = [
                f for f in all_funcs 
                if f and not f.startswith('_') and not f.startswith('__') and '@@' not in f
            ]
        except subprocess.CalledProcessError:
            print("정의된 함수 목록을 가져오는데 실패했습니다.")
            defined_funcs = []
        
        # Always include main if available
        if 'main' not in defined_funcs and defined_funcs != ['']:
            defined_funcs.append('main')
            
        return list(set(defined_funcs))
    
    def run_ghidra(self):
        # 전체 경로 계산
        binary_path = os.path.abspath(self.path)
        script_path = os.path.abspath(self.decompile_script)
        parse_path = os.path.abspath(self.parse_script)
        project_name = "tmp_ghidra_proj"
        # 명령어 구성
        cmd = [
            self.ghidra_path,
            self.project_path,
            project_name,
            "-import", binary_path,
            "-postScript", script_path, f"{self.path}_ghidra.c",
            '-postScript', parse_path, #기존 parse_global.py에서 절대경로 하드코딩으로 수정 
            "-deleteProject",  # 완료 후 프로젝트 삭제
        ]
        # 명령 실행
        try:
            subprocess.run(cmd, check=True)
            print(f"[*] Succeess to Ghidra decompile: {self.path}")
            with open(f"{self.path}_ghidra.c", "r") as f:
                self.ghidra_decompile = f.read()
            subprocess.run(["rm", f"{self.path}_ghidra.c"], check=True)
        except Exception as e:
            print(f"[!] Error occured: {e}")
    
    def classfy_decompile_func(self):
        for func_name in self.user_funcs:
            c_func = []
            flag = 0
            for line in self.ghidra_decompile.split('\n'):
                if f"Function: {func_name}" in line:#**Replace** main with the function name you want to decompile.
                    flag = 1
                    c_func.append(line)
                    continue
                if flag:
                    if '// Function:' in line:
                        if len(c_func) > 1:
                            break
                    c_func.append(line)
            if flag == 0:
                raise ValueError('bad case no function found')
            for idx_tmp in range(1,len(c_func)):##########remove the comments
                if func_name in c_func[idx_tmp]:
                    break
                    
            c_func = c_func[idx_tmp:]
            res = '\n'.join(c_func).strip()
            self.func_decompiled[func_name] = res
        
    def extract_gloabl_var(self):
        """
        전역 변수 심볼을 순회하며,
        .data/.rodata 에서
         1) 포인터 배열 → char *name[…] = { <dereferenced or NULL> };
         2) ASCII 문자열 → char name[…] = "...";
         3) 단일 int → int name = 값;
         4) int 배열 → int name[…] = { ... };
         5) 그 외 바이트 배열 → unsigned char name[…] = {...};
        .bss/.tbss → char name[…];
        기타 → unsigned char name[…];
        """
        print("======================== Extract Global Variable ========================")
        self.global_var = {}
        with open(self.path, 'rb') as f:
            elf      = ELFFile(f)
            elf_type = elf['e_type']
            is_exec  = (elf_type == 'ET_EXEC')
            ptr_sz   = elf.elfclass // 8
            base     = self.pie_base or 0

            # 모든 섹션 정보 수집
            sections = []
            for sec in elf.iter_sections():
                if sec['sh_size'] == 0:
                    continue
                start = sec['sh_addr']
                end   = start + sec['sh_size']
                sections.append((start, end, sec['sh_offset'], sec))

            symtab = elf.get_section_by_name('.symtab')
            if not symtab:
                print("No .symtab")
                return

            for sym in symtab.iter_symbols():
                # 전역 객체만 선별
                if sym['st_info']['type'] != 'STT_OBJECT' or sym['st_info']['bind'] != 'STB_GLOBAL':
                    continue
                name = sym.name
                if not name or name.startswith('_') or name.startswith(('stdout','stdin','stderr')):
                    continue
                size    = sym['st_size']
                sec_idx = sym['st_shndx']
                if sec_idx == 'SHN_UNDEF':
                    continue
                sec = elf.get_section(sec_idx)
                sec_name = sec.name if sec else ''
                decl = None

                # .data/.rodata: 초기화된 변수 처리
                if sec_name in ('.data', '.rodata'):
                    sec_addr = sec['sh_addr']
                    sec_off  = sec['sh_offset']
                    file_off = sym['st_value'] - sec_addr + sec_off
                    f.seek(file_off)
                    data = f.read(size)

                    # 1) 포인터 배열 감지
                    if size > 0 and size % ptr_sz == 0:
                        cnt = size // ptr_sz
                        fmt = f"<{cnt}{'Q' if ptr_sz==8 else 'I'}"
                        ptrs = struct.unpack(fmt, data)
                        addrs = ptrs if is_exec else [p + base for p in ptrs]
                        valid = sum(1 for p in addrs if p != 0 and any(start <= p < end for start, end,_,_ in sections))
                        if valid >= (cnt/2):
                            init_vals = []
                            for p in addrs:
                                if p == 0:
                                    init_vals.append('NULL')
                                    continue
                                seg = next(((s,e,off,sec_obj) for s,e,off,sec_obj in sections if s <= p < e), None)
                                if seg:
                                    s,e,off,sec_obj = seg
                                    fpos = off + (p - s)
                                    f.seek(fpos)
                                    raw = bytearray()
                                    while True:
                                        b = f.read(1)
                                        if not b or b == b'\x00': break
                                        raw += b
                                        if len(raw) > 256: break
                                    if 1 <= len(raw) <= 256 and all(c in string.printable.encode() for c in raw):
                                        init_vals.append(f'"{raw.decode()}"')
                                    else:
                                        init_vals.append(hex(p))
                                else:
                                    init_vals.append(hex(p))
                            decl = f'char *{name}[{cnt}] = {{{", ".join(init_vals)}}};'

                    # 2) 단일 int 감지
                    if decl is None and size == 4:
                        val = struct.unpack('<I', data)[0]
                        decl = f'int {name} = {val};'
                        
                    # 3) ASCII 문자열 감지
                    if decl is None and all((c in string.printable.encode() or c == 0) for c in data):
                        end = data.find(b'\x00')
                        if 0 < end < size:
                            s = data[:end].decode('ascii', errors='replace')
                            decl = f'char {name}[{end+1}] = "{s}";'

                    # 4) int 배열
                    if decl is None and size > 4 and size % 4 == 0:
                        cnt = size // 4
                        vals = struct.unpack(f'<{cnt}I', data)
                        decl = f'int {name}[{cnt}] = {{{", ".join(map(str, vals))}}};'

                    # 5) fallback 바이트 배열
                    if decl is None:
                        vals = ', '.join(hex(b) for b in data)
                        decl = f'unsigned char {name}[{size}] = {{{vals}}};'
                
                # .bss/.tbss: 초기화되지 않은 변수
                elif sec_name in ('.bss', '.tbss'):
                    if decl is None and size == 4:
                        decl = f'int {name};'
                    elif decl is None and size == 8:
                        decl = f'long {name};'
                    else:
                        decl = f'char {name}[{size}];'

                # 기타 섹션
                else:
                    decl = f'unsigned char {name}[{size}];'

                self.global_var[name] = decl

        # 결과 출력
        print("Extracted global vars:")
        for n, d in self.global_var.items():
            print(f"  {n}: {d}")

  
    def decompile(self):
        self.check_pie_and_base()
        self.disassemble_binary()
        self.extract_user_func()
        self.run_ghidra()
        self.classfy_decompile_func()
        self.extract_gloabl_var()
        

if __name__ == "__main__":
    analyzer = GhidraAnalyzer(file_path="sample/off_by_one_001",
                              ghidra_path=GHIDRA_PATH,
                              decompile_script=DECOMPILE_SCRIPT_PATH,
                              parse_script=PARSE_SCRIPT_PATH)
    
    analyzer.decompile()