import os
import csv
import time
import threading
from django.http import JsonResponse
from config import *
import sys
sys.path.append(CURRENT_DIR)
from LLM4Module.codeql import *

# 한 번 처리된 파일명을 저장할 집합
processed_taint_files = set()
# 파일명별 Lock 저장
_taint_locks = {}
# Lock 사전 접근 보호
_locks_guard = threading.Lock()

columns = ["Name", "Description", "Severity", "Message", "Path", 
           "Start line", "Start column", "End line", "End column"]

def taint_func(request, filename):
    if request.method != "POST":
        return JsonResponse({"error": "POST 요청만 가능합니다!"}, status=405)

    input_file = f"{filename}.c"
    input_root = INPUT_ROOT
    output_dir = TAINT_OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    csv_name = f"{filename}_security_extended.csv"
    csv_path = os.path.join(output_dir, csv_name)

    # ==== 동시 요청 방지 ====
    with _locks_guard:
        lock = _taint_locks.setdefault(filename, threading.Lock())
    if not lock.acquire(blocking=False):
        return JsonResponse(
            {"error": "이미 taint 분석 중입니다. 잠시 후 다시 시도하세요."},
            status=429
        )

    # 아직 한 번도 처리된 적이 없으면 taint 분석 실행
    if filename not in processed_taint_files:
        try:
            taint = CodeQL(
                source_file=input_file,
                source_root=input_root,
                result_dir=output_dir
            )
            taint.run(1)
            time.sleep(10)  # 분석 대기
            processed_taint_files.add(filename)
        finally:
            lock.release()
    else:
        # 이미 완료된 경우 lock 해제
        lock.release()

    # CSV를 읽어서 JSON으로 반환
    parsed_data = []
    try:
        with open(csv_path, mode="r", encoding="utf-8") as file:
            reader = csv.reader(file)
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
