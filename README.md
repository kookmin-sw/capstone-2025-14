# 🧠 Automated Binary Vulnerability Analysis Using LLMs

<mark>LLM을 이용하여 컴파일된 바이너리를 **실행 가능한 소스코드**로 디컴파일하고, 이를 바탕으로 **CodeQL**·**Taint 분석**을 자동화하는 도구입니다.</mark>

---

## 📌 프로젝트 개요

### 🔍 문제 정의

기존 디컴파일러(IDA Pro, Binary Ninja)는 비용이 매우 높거나, 무료 도구(Ghidra 등)는 재실행 가능한 형태의 코드가 아닌 단순한 pseudo-code 수준의 결과만 제공합니다. 이로 인해 디컴파일된 코드를 기반으로 정적 분석(CodeQL) 및 동적 분석(AFL Fuzzer)을 적용하기 어려웠습니다.

### 💡 해결 방법

본 프로젝트는 LLM4Decompile 모델을 활용하여 함수 단위의 어셈블리어 혹은 Ghidra 디컴파일 결과를 LLM에 입력하고, 실행 가능한 형태의 C 소스코드로 디컴파일합니다.  
- 전역 변수 등의 정보는 LLM이 완전하게 추론할 수 없기 때문에, 이를 별도로 분석/추출하여 디컴파일된 함수들과 조합해 최종 실행 가능한 소스코드를 생성합니다.  
- 생성된 코드는 CodeQL 정적 분석 및 Taint 분석에 즉시 활용 가능하며, 분석 결과는 시각적으로 확인할 수 있습니다.

---

## 🔧 기술 스택 및 도구
### Language
![python](https://img.shields.io/badge/Python-14354C?style=for-the-badge&logo=python&logoColor=white) ![javascript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=JavaScript&logoColor=white) ![html](https://img.shields.io/badge/HTML-239120?style=for-the-badge&logo=html5&logoColor=white) ![css](https://img.shields.io/badge/CSS-239120?&style=for-the-badge&logo=css3&logoColor=white)  

### Framework
![dJango](https://img.shields.io/badge/Django-092E20?style=for-the-badge&logo=django&logoColor=white
)  

### Tool
[![Ghidra](https://img.shields.io/badge/Ghidra-decompiler-red)](https://github.com/NationalSecurityAgency/ghidra)  
[![OBJdump](https://img.shields.io/badge/OBJdump-disassembler-blue)](https://www.gnu.org/software/binutils/)  
[![GCC](https://img.shields.io/badge/GCC-compiler-blue)](https://gcc.gnu.org/)  
[![CodeQL](https://img.shields.io/badge/CodeQL-security-green)](https://github.com/github/codeql)  
[![LLM4Decompile](https://img.shields.io/badge/LLM4Decompile-LLM_Model-purple)](https://github.com/albertan017/LLM4Decompile)

---

## 🚀 주요 기능

| 기능 | 설명 |
|------|------|
| 🔼 바이너리 업로드 | 사용자가 분석하고자 하는 바이너리를 업로드 |
| 🧩 디컴파일 | Ghidra 혹은 objdump를 통해 추출한 함수 단위의 코드와 전역 변수를 LLM을 통해 실행 가능한 형태의 C 코드로 디컴파일 |
| 📊 CodeQL 분석 | 디컴파일된 코드를 정적으로 분석하여 취약점을 자동 탐지 |
| 🧬 Taint 분석 | CodeQL 기반의 Taint 분석 수행 및 결과 제공 |

---

## 🛡️ List of Covered CWEs

<details>
  <summary>Show Covered CWEs</summary>

  <table>
    <thead>
      <tr>
        <th>CWE</th>
        <th>Type</th>
        <th>Description</th>
      </tr>
    </thead>
    <tbody>
      <tr>
        <td>CWE-014</td>
        <td>Compiler Removal of Code to Clear Buffers</td>
        <td>최적화 컴파일러가 민감 데이터 삭제용 코드를 제거하여 메모리에 민감 데이터가 남아 있게 되는 취약점</td>
      </tr>
      <tr>
        <td>CWE-020</td>
        <td>Improper Input Validation</td>
        <td>입력값을 올바르게 검증하지 않아 예기치 않은 동작이나 보안 결함으로 이어지는 취약점</td>
      </tr>
      <tr>
        <td>CWE-022</td>
        <td>Improper Limitation of a Pathname to a Restricted Directory</td>
        <td>경로 조작(path traversal) 공격을 통해 허가되지 않은 디렉터리/파일에 접근할 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-078</td>
        <td>OS Command Injection</td>
        <td>외부 입력을 통해 운영체제 명령 실행을 허용하여 임의 명령이 수행될 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-079</td>
        <td>Cross-site Scripting (XSS)</td>
        <td>입력값에 스크립트를 삽입해 다른 사용자의 브라우저에서 실행되도록 하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-089</td>
        <td>SQL Injection</td>
        <td>입력값으로 악의적 SQL 구문을 삽입하여 데이터베이스를 조작·유출할 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-114</td>
        <td>Process Control</td>
        <td>외부로부터 조작된 경로를 이용해 악성 모듈을 로드할 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-119</td>
        <td>Improper Restriction of Operations within the Bounds of a Buffer</td>
        <td>버퍼 오버플로우 등 메모리 경계를 넘어선 읽기/쓰기를 허용하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-120</td>
        <td>Buffer Copy without Checking Size of Input</td>
        <td>복사할 데이터 크기를 검사하지 않고 버퍼 복사를 수행해 오버플로우를 유발하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-121</td>
        <td>Stack-based Buffer Overflow</td>
        <td>스택 영역 버퍼 오버플로우로 인해 제어 흐름이 변조될 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-129</td>
        <td>Improper Validation of Array Index</td>
        <td>배열 인덱스를 경계 외 값으로 접근할 수 있어 메모리 손상이나 정보 유출이 발생하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-131</td>
        <td>Incorrect Calculation of Buffer Size</td>
        <td>버퍼 크기를 잘못 계산해 메모리 할당이 부족하거나 과다할 때 발생하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-134</td>
        <td>Uncontrolled Format String</td>
        <td>포맷 문자열 함수에 공격자가 제어 가능한 입력을 넘겨 포맷을 조작할 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-170</td>
        <td>Improper Null Termination</td>
        <td>문자열 종료 문자(<code>\0</code>)를 올바르게 처리하지 못해 버퍼 경계를 벗어나는 취약점</td>
      </tr>
      <tr>
        <td>CWE-190</td>
        <td>Integer Overflow or Wraparound</td>
        <td>정수 계산 결과가 최대값을 넘어서거나 래핑되어 오류가 발생하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-191</td>
        <td>Integer Underflow (Wrap or Wraparound)</td>
        <td>정수 계산 결과가 최소값 아래로 내려가거나 래핑되어 오류가 발생하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-193</td>
        <td>Off-by-one Error</td>
        <td>반복문 경계 조건이 하나 모자라거나 남아 잘못된 메모리 접근을 유발하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-253</td>
        <td>Incorrect Check of Function Return Value</td>
        <td>함수 반환값을 잘못 검사하거나 무시하여 오류 상태를 놓치는 취약점</td>
      </tr>
      <tr>
        <td>CWE-290</td>
        <td>Authentication Bypass by Spoofing</td>
        <td>스푸핑 등을 이용해 인증을 우회할 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-295</td>
        <td>Improper Certificate Validation</td>
        <td>SSL/TLS 인증서 검증을 제대로 수행하지 않아 위조된 인증서를 신뢰하게 되는 취약점</td>
      </tr>
      <tr>
        <td>CWE-311</td>
        <td>Missing Encryption of Sensitive Data</td>
        <td>민감 데이터를 암호화하지 않고 전송해 중간에 탈취될 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-313</td>
        <td>Cleartext Storage of Sensitive Information</td>
        <td>민감 정보를 암호화 없이 저장해 디스크 탈취 시 노출되는 취약점</td>
      </tr>
      <tr>
        <td>CWE-319</td>
        <td>Cleartext Transmission of Sensitive Information</td>
        <td>민감 정보를 암호화 없이 전송해 네트워크 상에서 탈취될 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-326</td>
        <td>Inadequate Encryption Strength</td>
        <td>약한 암호화 알고리즘 사용으로 암호문이 비교적 쉽게 해독될 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-327</td>
        <td>Use of a Broken or Risky Cryptographic Algorithm</td>
        <td>알려진 취약점이 있는 암호 알고리즘을 사용하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-367</td>
        <td>Time-of-Check Time-of-Use (TOCTOU) Race Condition</td>
        <td>검사 시점과 사용 시점 사이의 경쟁 조건으로 권한 우회나 데이터 무결성 손상이 발생하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-416</td>
        <td>Use After Free</td>
        <td>해제된 메모리를 다시 접근·사용하여 충돌이나 코드 실행이 가능한 취약점</td>
      </tr>
      <tr>
        <td>CWE-428</td>
        <td>Untrusted Search Path</td>
        <td>라이브러리·모듈 로드 시 경로 신뢰성을 검사하지 않아 악성 코드를 로드할 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-457</td>
        <td>Use of Uninitialized Variable</td>
        <td>초기화되지 않은 변수를 사용해 예측 불가능한 동작이나 정보 유출이 발생하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-468</td>
        <td>Incorrect Pointer Scaling</td>
        <td>포인터 산술 연산 시 크기 단위를 잘못 적용해 잘못된 메모리 접근이 발생하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-497</td>
        <td>Exposure of System Data to an Unauthorized Control Sphere</td>
        <td>시스템 내부 정보를 외부에 과도하게 노출하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-570</td>
        <td>Expression is Always False</td>
        <td>항상 거짓으로 평가되는 논리 표현식으로 인해 분기가 실행되지 않거나 불필요한 검사가 발생하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-611</td>
        <td>Improper Restriction of XML External Entity Reference (XXE)</td>
        <td>외부 엔터티(XML External Entity)를 잘못 처리해 SSRF나 파일 유출이 가능한 취약점</td>
      </tr>
      <tr>
        <td>CWE-676</td>
        <td>Use of Potentially Dangerous Function</td>
        <td>보안상 위험한 함수(e.g. <code>strcpy</code>, <code>gets</code>)를 사용하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-704</td>
        <td>Incorrect Type Conversion or Cast</td>
        <td>잘못된 형 변환/캐스트로 인한 데이터 손상 또는 오류가 발생하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-732</td>
        <td>Incorrect Permission Assignment for Critical Resource</td>
        <td>파일·리소스 권한을 과도하게 부여해 권한 상승이 가능한 취약점</td>
      </tr>
      <tr>
        <td>CWE-764</td>
        <td>Multiple Locks of a Critical Resource</td>
        <td>동일 자원에 중복으로 잠금을 시도해 교착 상태(데드락)가 발생할 수 있는 취약점</td>
      </tr>
      <tr>
        <td>CWE-807</td>
        <td>Reliance on Untrusted Inputs in a Security Decision</td>
        <td>보안 결정을 위해 신뢰할 수 없는 입력값을 사용하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-835</td>
        <td>Infinite Loop</td>
        <td>특정 조건에서 탈출되지 않는 무한 루프가 발생해 서비스 거부를 유발하는 취약점</td>
      </tr>
      <tr>
        <td>CWE-843</td>
        <td>Access of Resource Using Incompatible Type (‘Type Confusion’)</td>
        <td>잘못된 타입으로 객체/리소스에 접근해 메모리 손상이나 권한 우회가 발생하는 취약점</td>
      </tr>
    </tbody>
  </table>
</details>

---

## 🛠️ 사용 방법

### 설치 및 환경 구성

```bash
git clone https://github.com/kookmin-sw/capstone-2025-14  
cd settings  
./codeqlInstall.sh  
./GhidraModelInstall.sh
```
### 실행 방법
```bash
cd project  
python3 manage.py runserver [ip 주소] [port 번호]
```
---

## ⚙️ 시스템 아키텍처

<div align="center">
  <img 
    src="https://github.com/kookmin-sw/capstone-2025-14/blob/master/images/architecture.png" 
    alt="System Architecture" 
    width="600" 
  />
</div>

---

## ↖ Code Flow
<div align="center">
  <img 
    src="https://github.com/kookmin-sw/capstone-2025-14/blob/master/images/codeflow.png" 
    alt="Code Flow" 
    width="600" 
  />
</div>

---

## 👨‍👩‍👧‍👦 팀원 소개

| 이름 | 역할 |
|------|------|
| 황승재 | PM, CodeQL, LLM 디컴파일 개발 |
| 신윤제 | CodeQL, LLM 디컴파일 개발 |
| 최원준 | 백엔드 및 프론트엔드 개발 |

---

## 📈 향후 계획

- AFL 기반의 동적 분석 모듈 연동  
- 전역 변수 및 구조체 자동 복원 정확도 향상  
- 다양한 LLM 모델 비교 및 성능 평가  
- 분석 리포트 자동 생성 기능 추가  

---

