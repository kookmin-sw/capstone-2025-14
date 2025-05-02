#!/usr/bin/env bash
#
# CodeQL을 사용하여 Connman을 분석하는 예시 자동화 스크립트
# --------------------------------------------------------
# 1) 필수 패키지 설치 (git, build-essential, clang 등)
# 2) CodeQL CLI 다운로드 및 설치
# 3) Connman 소스코드 준비 (tar.gz 등)
# 4) CodeQL 데이터베이스 생성
# 5) CodeQL 기본/확장 보안 쿼리 실행 및 결과 확인

# 스크립트 실행 중 오류 발생 시 중단
set -e

# --------------------------------------------------------
# 1. 필수 패키지 설치
# --------------------------------------------------------
echo "[1/6] 필수 패키지 설치 중..."
sudo apt-get update -y
sudo apt-get install -y git build-essential clang wget unzip

# --------------------------------------------------------
# 2. CodeQL CLI 다운로드 및 설치
# --------------------------------------------------------
echo "[2/6] CodeQL CLI 다운로드 및 설치 중..."

# CodeQL CLI 버전(예: v2.20.5), 아키텍처(64bit) 등 상황에 맞춰 조정
CODEQL_VERSION="2.20.5"
CODEQL_ZIP="codeql-linux64.zip"
CODEQL_URL="https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/${CODEQL_ZIP}"
INSTALL_DIR="$HOME/codeql"

# 이미 디렉토리가 있으면 덮어쓸 수 있도록 제거 (원치 않으면 주석 처리)
rm -rf "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"
cd "${INSTALL_DIR}"

echo "  > 다운로드: ${CODEQL_URL}"
wget -q "${CODEQL_URL}"

echo "  > 압축 해제..."
unzip -q "${CODEQL_ZIP}"
rm "${CODEQL_ZIP}"  # 더 이상 필요 없으면 삭제

# PATH 설정 (Bash 기준 / Zsh 등 사용 시 ~/.zshrc에 추가)
if ! grep -q 'codeql/codeql' ~/.bashrc; then
  echo "export PATH=\$PATH:$HOME/codeql/codeql" >> ~/.bashrc
fi

# 현재 쉘 세션에도 즉시 반영
export PATH=$PATH:$HOME/codeql/codeql

echo "  > 설치 완료. CodeQL 버전:"
codeql version

# --------------------------------------------------------
# 3. Connman 소스 준비
# --------------------------------------------------------
# 예시로 connman-1.43.tar.gz가 현재 스크립트 디렉토리에 있다고 가정
# 실제로는 wget 등을 통해 직접 다운로드하거나, 원하는 버전을 사용
echo "[3/6] Connman 소스 준비 중..."
cd ~
if [ ! -f "./connman-1.43.tar.gz" ]; then
  echo "connman-1.43.tar.gz 파일이 없습니다. 다운로드 또는 위치를 확인하세요."
  exit 1
fi

# clean up
rm -rf connman-1.43
tar -xvf connman-1.43.tar.gz >/dev/null 2>&1
cd connman-1.43

# --------------------------------------------------------
# 4. CodeQL 데이터베이스 생성
# --------------------------------------------------------
echo "[4/6] CodeQL 데이터베이스 생성 중..."
# 디렉토리: db-connman
codeql database create db-connman \
  --overwrite \
  --language=c \
  --command='sh -c "./bootstrap && ./configure CFLAGS=\"-g -O0\" CXXFLAGS=\"-g -O0\" --prefix=/usr --sysconfdir=/etc --localstatedir=/var --disable-dependency-tracking && make"'

echo "  > db-connman 폴더가 생성되었습니다."

# --------------------------------------------------------
# 5. CodeQL 기본 보안 쿼리 실행
# --------------------------------------------------------
echo "[5/6] CodeQL 기본 보안 쿼리 실행 중..."

# 쿼리 팩이 없는 경우 github/codeql 저장소를 클론
cd ~
if [ ! -d "./codeql-repo" ]; then
  echo "  > codeql-repo (쿼리 스위트) 저장소가 없어 새로 클론합니다."
  git clone https://github.com/github/codeql.git codeql-repo
fi

# 분석 대상 DB 디렉토리로 이동
cd ~/connman-1.43

# 기본 C/C++ 보안 스위트
echo "  > cpp-code-scanning.qls 스위트 실행..."
codeql database analyze db-connman \
  ~/codeql-repo/cpp/ql/src/codeql-suites/cpp-code-scanning.qls \
  --format=csv \
  --output=connman-security.csv

echo "  > 결과 출력 (connman-security.csv)..."
cat connman-security.csv || true

# --------------------------------------------------------
# 6. CodeQL 확장 보안 쿼리 실행(선택)
# --------------------------------------------------------
echo "[6/6] CodeQL 확장 보안 쿼리 실행 중..."
codeql database analyze db-connman \
  ~/codeql-repo/cpp/ql/src/codeql-suites/cpp-security-extended.qls \
  --format=csv \
  --output=connman-security-extended.csv

echo "  > 결과 출력 (connman-security-extended.csv)..."
cat connman-security-extended.csv || true

# --------------------------------------------------------
# 스크립트 종료
# --------------------------------------------------------
echo "모든 작업이 완료되었습니다!"
echo "분석 결과는 다음 두 CSV 파일에서 확인하실 수 있습니다:"
echo "  1) connman-security.csv"
echo "  2) connman-security-extended.csv"
