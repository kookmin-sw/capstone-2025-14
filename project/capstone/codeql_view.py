import sys
sys.path.append('/home/user/codebugger')

import csv
import os
import json
import time
from django.http import JsonResponse
from django.conf import settings
from LLM4Module.codeql import *

columns = ["Name", "Description", "Severity", "Message", "Path", 
           "Start line", "Start column", "End line", "End column"]

def codeql_result(request, filename):
    if request.method == "POST":
        input_file = f"{filename}.c"
        input_root = "/home/user/codebugger/media/downloads/"
        output_file = f"/home/user/codebugger/media/codeql_result/"
        codeql = CodeQL(source_file=input_file, source_root=input_root, result_dir=output_file)
        codeql.remove_database()
        codeql.static_run()
        parsed_data = []  # 변환된 데이터를 저장할 리스트
        time.sleep(10)
        with open(output_file+"output_security_extended.csv", mode="r", encoding="utf-8") as file:
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
