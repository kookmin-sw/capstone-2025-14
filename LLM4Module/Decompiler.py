from collections import deque
import gc, re
from transformers import AutoTokenizer, AutoModelForCausalLM
import torch
from LLM4Module.Analyzer import AssemblyAnalyzer, GhidraAnalyzer #서버로 돌릴 경우 from LLM4Module.Analyzer import AssemblyAnalyzer

        
class AssemblyDecompiler:
    def __init__(self, model_path: str, cuda_device: str, analyzer:AssemblyAnalyzer):
        self.model_path = model_path
        self.cuda_device = cuda_device
        self.tokenizer, self.model = self.load_model()
        self.analyzer = analyzer
        self.prompt = None
        self.output = None
        self.decompile_res = dict()
        
    def __del__(self):
        del self.tokenizer, self.model
        gc.collect()
        
    def load_model(self):
        """LLM 모델 및 토크나이저 로드"""
        print("모델 로드 중...")
        tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        model = AutoModelForCausalLM.from_pretrained(
            self.model_path, torch_dtype=torch.float16
        ).to(self.cuda_device)
        print("모델 로드 성공!")
        return tokenizer, model
    
    def gen_prompt(self, func_name:str, asm_code:str):
        before = f"# This is the assembly code for function <{func_name}>:\n"

        used_funcs = self.analyzer.func_call.get(func_name, [])
        if used_funcs:
            before += f"# This function calls: {', '.join(used_funcs)}\n"

        asm_blocks = f"\n<{func_name}>\n{asm_code}\n"

        after = ""
        STD_FUNC_SIG = {
            'read': 'ssize_t read(int fd, void *buf, size_t count);',
            'write': 'ssize_t write(int fd, const void *buf, size_t count);',
            'printf': 'int printf(const char *format, ...);',
            'scanf': 'int scanf(const char *format, ...);',
            'exit': 'void exit(int status);',
            'puts': 'int puts(const char *s);',
            'gets': 'char *gets(char *s);',
            'strlen': 'size_t strlen(const char *s);',
            'memcpy': 'void *memcpy(void *dest, const void *src, size_t n);',
            'malloc': 'void *malloc(size_t size);',
            'free': 'void free(void *ptr);',
            'initialize': 'void initialize();',
        }

        proto_lines = [f"# {STD_FUNC_SIG[f]}" for f in used_funcs if f in STD_FUNC_SIG]
        if proto_lines:
            after += "# Function prototypes (assumed to be declared already):\n"
            after += "\n".join(proto_lines) + "\n\n"

        #after += "# Lines like 'sub $0xNN,%esp   # Total local variable : N bytes' indicate stack buffer allocations.\n"
        #after += "# Use these buffers in read/printf etc. instead of new variables.\n\n"
        after += "Rules:\n"
        after += "1. Don't use any functions or strings other than the ones This function calls or refers.\n" 
        after += "2. Do NOT invent or insert any string literals (like \"%s\") that are not explicitly present in the assembly.\n"
        after += "3. If a format string is used in format-used function(e.g. printf, scanf, sprintf), it must come from memory (e.g., a push to .rodata).\n"
        after += "4. If a push instruction has a string literal as a comment (e.g., push $0x8048781   # \"Hello\"), only then may you use it.\n\n"
        
        after += "Request: Write a complete C function that implements this assembly code with above Rules.\n"

        self.prompt = before + asm_blocks + after
        print(self.prompt)
    
    def decompile_func(self):
        inputs = self.tokenizer(self.prompt, return_tensors="pt").to(self.cuda_device)
        with torch.no_grad():
            outputs = self.model.generate(**inputs, max_new_tokens=2048)
            c_code = self.tokenizer.decode(outputs[0][len(inputs.input_ids[0]):-1])
            
            print("================decompiled binary================")
            print(c_code)
            return c_code
    
    def decompile_binary(self):
        for name, code in self.analyzer.func_disassemble.items():
            self.gen_prompt(func_name=name, asm_code=code)
            dec_code = self.decompile_func()
            self.decompile_res[name] = dec_code
    
    def gen_output(self, output_path:str):
        with open(output_path, 'w') as f:
            f.write("#include <stdio.h>\n")
            f.write("#include <stdlib.h>\n")
            f.write("#include <string.h>\n")
            f.write("#include <signal.h>\n")
            f.write("#include <unistd.h>\n")
            for name, code in self.decompile_res.items():
                f.write(code + '\n\n')
    
    def decompile(self, output_path:str):
        self.decompile_binary()
        self.gen_output(output_path=output_path)
    
class GhidraDecompiler:
    def __init__(self, model_path: str, analyzer:GhidraAnalyzer):
        self.model_path = model_path
        self.tokenizer, self.model = self.load_model()
        self.analyzer = analyzer
        self.prompt = None
        self.output = None
        self.decompile_res = dict()
        
    def __del__(self):
        del self.tokenizer, self.model
        gc.collect()
        
    def load_model(self):
        """LLM 모델 및 토크나이저 로드"""
        print("모델 로드 중...")
        tokenizer = AutoTokenizer.from_pretrained(self.model_path)
        model = AutoModelForCausalLM.from_pretrained(
            self.model_path, torch_dtype=torch.float16, device_map="auto"
        )
        print("모델 로드 성공!")
        return tokenizer, model

    def gen_prompt(self, func_name:str, decom_code:str):
        before = ""
        before += f"# This is the assembly code:\n"#prompt
        
        after = ""
        after += "\n# What is the source code?\n"#prompt
        self.prompt = before + decom_code + after

    def decompile_func(self):
        inputs = self.tokenizer(self.prompt, return_tensors="pt").to(self.model.device)
        with torch.no_grad():
            outputs = self.model.generate(**inputs, max_new_tokens=2048)
            c_code = self.tokenizer.decode(outputs[0][len(inputs.input_ids[0]):-1])
            c_code = c_code.replace("__isoc99_scanf", "scanf")
            print("================================decompiled binary================================")
            print(c_code)
            return c_code
    
    def gen_output(self, output_path:str):
        library = {'stdio.h' : ['printf', 'fprintf', 'sprintf', 'snprintf', 'scanf', 'fscanf', 'sscanf', 'putchar', 'puts', 'fputs', 'getchar', 'gets', 'fgets', 'fopen', 'freopen', 'fclose', 'fread', 'fwrite', 'fseek', 'ftell', 'rewind', 'feof', 'ferror', 'clearerr', 'perror', 'remove', 'rename', 'tmpfile', 'tmpnam', ],
                   'stdlib.h' : ['malloc', 'calloc', 'realloc', 'free', 'exit', 'abort', 'atexit', '_Exit', 'atoi', 'atol', 'atof', 'strtol', 'strtoul', 'strtod', 'strtof', 'strtoll', 'rand', 'srand', 'random', 'srandom', 'system', 'qsort', 'bsearch', ],
                   'string.h' : ['strlen', 'strcpy', 'strncpy', 'strcat', 'strncat', 'strcmp', 'strncmp', 'strchr', 'strrchr', 'strstr', 'strpbrk', 'memset', 'memcpy', 'memmove', 'memcmp', 'strtok', ],
                   'math.h' : ['sqrt', 'pow', 'exp', 'log', 'log10', 'sin', 'cos', 'tan', 'asin', 'acos', 'atan2', 'ceil', 'floor', 'fabs', 'fmod', 'hypot', 'isnan', 'isinf', ],
                   'ctype.h' : ['isalpha', 'isdigit', 'isalnum', 'isxdigit', 'islower', 'isupper', 'isspace', 'isblank', 'iscntrl', 'ispunct', 'tolower', 'toupper'], 
                   'time.h' : ['time', 'ctime', 'asctime', 'localtime', 'gmtime', 'mktime', 'difftime', 'clock', 'strftime', 'struct tm', ],
                   'stdbool.h' : ['bool', 'true', 'false', ],
                   'signal.h' : ['signal', 'raise', 'SIGINT', 'SIGTERM', 'SIGKILL', 'SIGSEGV', 'SIGABRT', 'SIG_DFL', 'SIG_IGN', ],
                   'unistd.h' : ['read', 'write', 'fork', 'exec', 'getpid', 'getppid', 'sleep', 'usleep', 'alarm', 'chdir', 'getcwd', 'access', 'close', 'dup', 'pipe', 'isatty', 'ttyname', 'sbrk', 'brk', ]}
        
        res = ''
        declarations = self.extract_function_declarations(self.decompile_res)
        res += declarations + "\n" + res
        
        for name, code in self.analyzer.global_var.items():
            res += f"{code}\n"
        res += "\n"
        
        
        with open(output_path, 'w') as f:
            for name, code in self.decompile_res.items():
                res += code + '\n\n'
            symbol_to_header = {}
            for header, symbols in library.items():
                for sym in symbols:
                    symbol_to_header[sym] = header

            # C 코드에서 등장한 모든 식별자 추출
            tokens = set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', res))
            inferred_headers = set()
            for token in tokens:
                if token in symbol_to_header:
                    inferred_headers.add(symbol_to_header[token])
            for header in inferred_headers:
                res = f"#include <{header}>\n" + res
            f.write(res)
    
    def extract_function_declarations(self, decompile_res: dict, skip_names=('main', '_start')) -> str:
        declaration_code = ""
        func_pattern = re.compile(
            r'^\s*([a-zA-Z_][\w\s\*\[\]]+?)\s+([a-zA-Z_][\w]*)\s*\((.*?)\)\s*\{',
            re.MULTILINE
        )
        for func_name, code in decompile_res.items():
            if func_name in skip_names:
                continue
            match = func_pattern.search(code)
            if match:
                ret_type = match.group(1).strip()
                name = match.group(2).strip()
                args = match.group(3).strip()
                if args == "":
                    args = "void"
                declaration_code += f"{ret_type} {name}({args});\n"
        
        return declaration_code
    
    def decompile(self, output_path:str):
        for func_name, code in self.analyzer.func_decompiled.items():
            self.gen_prompt(func_name=func_name, decom_code=code)
            result = self.decompile_func()
            self.decompile_res[func_name] = result
        self.gen_output(output_path=output_path)