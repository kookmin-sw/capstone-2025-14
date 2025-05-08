import os
import csv
from django.http import JsonResponse
from config import *
import sys
sys.path.append(CURRENT_DIR)
from LLM4Module.codeql import *

# 한 번 분석한 파일명을 저장할 집합
processed_codeql_files = set()

columns = ["Name", "Description", "Severity", "Message", 
           "Path", "Start line", "Start column", 
           "End line", "End column"]

def codeql_result(request, filename):
    if request.method != "POST":
        return JsonResponse({"error": "POST 요청만 가능합니다!"}, status=405)

    # 입력/출력 경로 설정
    input_file = f"{filename}.c"
    input_root = INPUT_ROOT
    output_dir = CODEQL_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    csv_name = f"{filename}_security.csv"
    csv_path = os.path.join(output_dir, csv_name)

    # 아직 한 번도 처리된 적이 없으면 무조건 CodeQL 실행
    if filename not in processed_codeql_files:
        codeql = CodeQL(
            source_file=input_file,
            source_root=input_root,
            result_dir=output_dir
        )
        codeql.run(0)
        processed_codeql_files.add(filename)

    # CSV 파일을 읽어서 JSON으로 반환
    parsed_data = []
    try:
        with open(csv_path, mode="r", encoding="utf-8") as f:
            reader = csv.reader(f)
            for row in reader:
                if len(row) == len(columns):
                    entry = {
                        columns[i]: row[i]
                        for i in range(len(columns))
                        if columns[i] != "Path"
                    }
                    parsed_data.append(entry)
    except FileNotFoundError:
        return JsonResponse(
            {"error": f"{csv_name} 파일을 찾을 수 없습니다."},
            status=500
        )

    return JsonResponse(parsed_data, safe=False)
