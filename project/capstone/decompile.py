
import os
import io
import subprocess
from django.http import JsonResponse
from django.conf import settings
from elftools.elf.elffile import ELFFile
import sys
import os

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.abspath(os.path.join(CURRENT_DIR, "../../"))

sys.path.append(PARENT_DIR)
from config import *
sys.path.append(CURRENT_DIR)
from LLM4Module.Analyzer import *
from LLM4Module.Decompiler import *

def is_elf(file_bytes):
    if len(file_bytes) < 4:
        return False
    return file_bytes[:4]==b"\x7fELF"

def has_symbols(file_bytes):
    stream = io.BytesIO(file_bytes)
    elffile = ELFFile(stream)
    symtab = elffile.get_section_by_name('.symtab')
    if symtab and symtab.num_symbols() > 0:
        return True
    return False

def decompile(request):
    if request.method == "POST" and request.FILES.get("file"):
        uploaded_file = request.FILES["file"]
        # 디버깅을 위한 로깅 추가
        print(f"Received file: {uploaded_file.name}, size: {uploaded_file.size} bytes")
        
        file_bytes = uploaded_file.read()

        #elf파일인지 확인
        if not is_elf(file_bytes):
            print("Not ELF file")
            return JsonResponse({"error": "Please upload ELF file"}, status=400)

        #symbol table이 존재하는지 확인
        if not has_symbols(file_bytes):
            print("No symbol table")
            return JsonResponse({"error": "Please upload file with symbol table"}, status=400)

        # 절대 경로 사용
        upload_dir = os.path.join(settings.MEDIA_ROOT, "uploads")
        download_dir = os.path.join(settings.MEDIA_ROOT, "downloads")
        file_path = os.path.join(upload_dir, uploaded_file.name)
        
        print(f"Upload directory: {upload_dir}")
        print(f"File path: {file_path}")
        
        try:
            # media/uploads 폴더 생성
            if not os.path.exists(upload_dir):
                os.makedirs(upload_dir)
                print(f"Created directory: {upload_dir}")

            #media/downloads 폴더 생성
            if not os.path.exists(download_dir):
                os.makedirs(download_dir)
                print(f"Created directory: {download_dir}")
                
            # 업로드된 파일 저장
            with open(file_path, "wb+") as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)
            
            #파일 권한 수정
            os.chmod(file_path,0o600)
            
            print(f"Changed file({file_path}) access permission")

            print(f"File saved successfully: {file_path}")
            
            #디컴파일 실행
            decompiled_code = run_decompiler(file_path)
            print(f"Decompilation completed, code length: {len(decompiled_code)}")
            
            #성공 시 반환
            return JsonResponse({
                "decompiledCode": decompiled_code,
                "downloadUrl": f"/capstone/api/download/{uploaded_file.name}.c"
            })
        except Exception as e:
            print(f"Error during decompilation: {str(e)}")
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request"}, status=400)

def run_decompiler(file_path):#def tmp(file_path):
    decompiled_output = f"{file_path}.c"
    decompiled_output_to_move = decompiled_output.replace("uploads","downloads")
    print(f"Decompiled output path: {decompiled_output_to_move}")

    try:
        #LLM decompile 실행
        test = GhidraAnalyzer(file_path=file_path,
                              ghidra_path=GHIDRA_PATH,
                              decompile_script=DECOMPILE_SCRIPT_PATH,
                              parse_script=PARSE_SCRIPT_PATH,)
        test.decompile()

        decompiler = GhidraDecompiler(model_path=MODEL_PATH, analyzer=test)
        decompiler.decompile(output_path=decompiled_output_to_move)
    except subprocess.CalledProcessError as e:
        print(f"Command execution failed: {str(e)}")
        return "Failed to execute decompiler mv_cmd"
    
    if os.path.exists(decompiled_output_to_move):
        try:
            with open(decompiled_output_to_move, "r") as f:
                content = f.read()
                print(f"Read {len(content)} bytes from output file")
                return content
        except Exception as e:
            print(f"Error reading output file: {str(e)}")
            return f"Failed to read decompiled file: {str(e)}"
    else:
        print(f"Output file does not exist: {decompiled_output_to_move}")
    
    return "Failed to decompile"
    