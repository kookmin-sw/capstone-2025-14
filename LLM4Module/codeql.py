import os
import subprocess
import shutil 

class CodeQL:
    def __init__(self, source_file:str, source_root:str, result_dir:str):
        self.source_root = source_root
        self.source_file = source_root + source_file
        self.result_dir = result_dir
        self.codeql_path = "/home/user/codeql/codeql/codeql"
        self.basic_query_suite = "/home/user/codeql-repo/cpp/ql/src/codeql-suites/cpp-code-scanning.qls"
        self.extended_query_suite = "/home/user/codeql-repo/cpp/ql/src/codeql-suites/cpp-security-extended.qls"
        self.taint_query = "/home/user/codeql-repo/cpp/ql/src/Security/CWE/custom/read_bof.ql"
        self.db_path = os.path.join(self.result_dir, "output_db")
        
    def static_run(self):
        tasks = [
            ("Data base", self.gen_database),
            #("Basic Analysis", self.basic_security_anaylsis),
            #("Expand Analysis", self.expand_security_analysis),
            ("Taint Analysis", self.taint_run),
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
        basic_result = os.path.join(self.result_dir, "output_security.csv")
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
        extended_result = os.path.join(self.result_dir, "output_security_extended.csv")
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
        taint_bqrs = os.path.join(self.result_dir, "output_taint.bqrs")
        taint_csv = os.path.join(self.result_dir, "output_taint.csv")
        print("Taint 분석 실행 중...")
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
    
    
def main():
    test = CodeQL('output.c', os.getcwd() + '/', 'taint_test')
    test.static_run()

if __name__ == "__main__":
    main()