import os
import subprocess
import shutil 
import ctypes
from config import *

class CodeQL:
    def __init__(self, source_file:str, source_root:str, result_dir:str, 
                 basic_csv="output_security.csv",
                 extended_csv="output_security_extended.csv",
                 taint_csv="output_taint.csv"):
        self.source_root = source_root
        self.source_file = source_root + "/" +source_file
        self.result_dir = result_dir
        self.cpp_ql_path = CPP_QL_PATH
        self.codeql_path = CODEQL_PATH
        self.basic_query_suite = f"{QUERY_SUITE}/cpp-code-scanning.qls"
        self.extended_query_suite = f"{QUERY_SUITE}/cpp-security-extended.qls"
        self.taint_query = f"{TAINT_QUERY}/queries/fsb.ql"
        self.taint_queries = [
            f"{TAINT_QUERY}/queries/fsb.ql"
        ]
        self.basic_csv = basic_csv
        self.extended_csv = extended_csv
        self.taint_csv = taint_csv
        self.db_path = os.path.join(self.result_dir, "output_db")
        
    def static_run(self):
        tasks = [
            ("Data base", self.gen_database),
            ("Basic Analysis", self.basic_security_anaylsis),
            #("Expand Analysis", self.expand_security_analysis),
        ]
        
        for name, func in tasks:
            res, err = func()
            if not res:
                print(f"{name} Error : {err}")
                print(err.stdout)
                print(err.stderr)
        
    def gen_database(self):
        self.remove_database()
        if os.path.exists(self.db_path):
            print(f"기존 데이터베이스 사용: {self.db_path}")
            return True, None
        else:
            # 데이터베이스 생성
            print(f"데이터베이스 생성 중: {self.db_path}")
            try:
                subprocess.run([
                    self.codeql_path, "database", "create",
                    self.db_path,
                    "--language=cpp",
                    f"--command=gcc -c {self.source_file}",
                    "--source-root=" + self.source_root
                ], check=True,
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, text=True)
                return True, None
            except subprocess.CalledProcessError as e:
                print(f"데이터베이스 생성 중 오류: {e}")
                return False, e
    
    def basic_security_anaylsis(self):
        """
        codeQL 기본 보안 분석
        """
        basic_result = os.path.join(self.result_dir, self.basic_csv)
        print(f"기본 보안 분석 실행 중...")
        try:
            subprocess.run([
                self.codeql_path, "database", "analyze",
                self.db_path,
                self.basic_query_suite,
                "--format=csv",
                f"--output={basic_result}"
            ], check=True,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, text=True)
            print(f"- 기본 보안 분석: {basic_result}")
            return True, None
        except subprocess.CalledProcessError as e:
            print(f"기본 분석 실행 중 오류: {e}")
            return False, e
            
    def expand_security_analysis(self):
        """
        codeQL 확장 보안 분석
        """
        extended_result = os.path.join(self.result_dir, self.extended_csv)
        print(f"확장 보안 분석 실행 중...")
        try:
            result = subprocess.run([
                self.codeql_path, "database", "analyze",
                self.db_path,
                self.extended_query_suite,
                "--format=csv",
                f"--output={extended_result}"
            ], check=True,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, text=True)
            print(f"- 확장 보안 분석: {extended_result}")
            return True, None
        except subprocess.CalledProcessError as e:
            print(f"확장 분석 실행 중 오류: {e}")
            return False, e
        
    def remove_database(self):
        """
        데이터베이스 삭제
        """
        if os.path.exists(self.db_path):
            print(f"데이터베이스 삭제 중: {self.db_path}")
            try:
                shutil.rmtree(self.db_path)
                print("데이터베이스 삭제 완료.")
                return True, None
            except Exception as e:
                print(f"데이터베이스 삭제 중 오류: {e}")
                return False, e
        else:
            print(f"삭제할 데이터베이스가 존재하지 않습니다: {self.db_path}")
            return True, None
    
    def taint_run(self):
        """
        CodeQL Taint Tracking 분석
        """
        self.gen_database()
        taint_bqrs = os.path.join(self.result_dir, "output_taint.bqrs")
        taint_csv = os.path.join(self.result_dir, self.taint_csv)
        print("Taint 분석 실행 중...")
        cmd = [
                self.codeql_path, "query", "run",
                self.taint_query,
                "--database", self.db_path,
                "--output", taint_bqrs
            ]
        cmd_str = " ".join(cmd)
        print(cmd_str)
        try:
            subprocess.run([
                self.codeql_path, "query", "run",
                self.taint_query,
                "--database", self.db_path,
                "--output", taint_bqrs
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # Decode the results to CSV
            subprocess.run([
                self.codeql_path, "bqrs", "decode",
                "--format=csv",
                f"--output={taint_csv}",
                taint_bqrs
            ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(f"- taint 분석 결과: {taint_csv}")
            return True, None
        except subprocess.CalledProcessError as e:
            print(f"taint 분석 실행 중 오류: {e}")
            return False, e
        
    def run(self, n):
        tasks = [
            # ("Data base", self.gen_database),
            ("Basic Analysis", self.basic_security_anaylsis),
            ("Expand Analysis", self.expand_security_analysis),
            ("Taint Analysis", self.taint_run)
        ]
        
            
        if 0 <= n < 3:
            # Data base 생성
            name = "Data base"
            func = self.gen_database
            
            res, err = func()
            if not res:
                print(f"{name} Error : {err}")
                print(err.stdout)
                print(err.stderr)
                return res, err
            
            # Task 실행
            name = tasks[n][0]
            func = tasks[n][1]
            res, err = func()
            if not res:
                print(f"{name} Error : {err}")
                print(err.stdout)
                print(err.stderr)
                return res, err
        else:
            print("Wrong Task Number!")
        return True, None
        
    
    
def main():
    test = CodeQL('output.c', os.getcwd() + '/', 'taint_test', extended_csv=f"output.csv")
    test.run(1)

if __name__ == "__main__":
    main()