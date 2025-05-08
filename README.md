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
[![Ghidra](https://img.shields.io/badge/Ghidra-reverse_engineering-red)](https://github.com/NationalSecurityAgency/ghidra)  
[![OBJdump](https://img.shields.io/badge/OBJdump-disassembler-blue)](https://www.gnu.org/software/binutils/)  
[![GCC](https://img.shields.io/badge/GCC-compiler-blue)](https://gcc.gnu.org/)  
[![CodeQL](https://img.shields.io/badge/CodeQL-security-green)](https://github.com/github/codeql)  
[![LLM4Decompile](https://img.shields.io/badge/LLM4Decompile-decompiler-purple)](https://github.com/llm4decompile/)

---

## 🚀 주요 기능

| 기능 | 설명 |
|------|------|
| 🔼 바이너리 업로드 | 사용자가 분석하고자 하는 바이너리를 업로드 |
| 🧩 디컴파일 | Ghidra 혹은 objdump를 통해 추출한 함수 단위의 코드와 전역 변수를 LLM을 통해 실행 가능한 형태의 C 코드로 디컴파일 |
| 📊 CodeQL 분석 | 디컴파일된 코드를 정적으로 분석하여 취약점을 자동 탐지 |
| 🧬 Taint 분석 | CodeQL 기반의 Taint 분석 수행 및 결과 제공 |

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

