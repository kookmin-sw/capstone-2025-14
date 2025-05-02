
import csv
import time
from django.http import JsonResponse
from config import *
import sys
sys.path.append(CURRENT_DIR)
from LLM4Module.codeql import *

columns = ["Name", "Description", "Severity", "Message", "Path", 
           "Start line", "Start column", "End line", "End column"]

def taint_func(request, filename):
    if request.method=="POST":
        input_file = f"{filename}.c"
        input_root = INPUT_ROOT
        output_file = TAINT_OUTPUT_DIR
        taint = CodeQL(source_file=input_file, source_root=input_root, result_dir=output_file)     
        taint.taint_run()
        parsed_data = []
        time.sleep(10)
        with open(output_file+"output_taint_extended.csv", mode="r", encoding="utf-8") as file:
            reader = csv.reader(file)  # 헤더 없이 읽기
            for row in reader:
                if len(row) == len(columns):
                    # "Path" 컬럼만 제외하고 dictionary 생성
                    entry = {
                        columns[i]: row[i]
                        for i in range(len(columns)) 
                        if columns[i] != "Path"  # Path 컬럼은 빼기
                    }
                    parsed_data.append(entry)
        return JsonResponse(parsed_data, safe=False)

    return JsonResponse({"error": "POST 요청만 가능합니다!"}, status=405)