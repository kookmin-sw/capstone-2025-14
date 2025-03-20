// dropzone과 파일 입력 요소 참조
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");

// 파일 정보 미리보기 업데이트 함수
function showUploadedFile() {
  if (fileInput.files.length > 0) {
    const file = fileInput.files[0];

    // 파일 크기를 읽기 쉽게 변환하는 헬퍼 함수
    function formatBytes(bytes) {
      if (bytes < 1024) return bytes + " Bytes";
      else if (bytes < 1048576) return (bytes / 1024).toFixed(2) + " KB";
      else if (bytes < 1073741824) return (bytes / 1048576).toFixed(2) + " MB";
      return (bytes / 1073741824).toFixed(2) + " GB";
    }

    // 파일 정보를 아이콘, 이름, 크기 형식으로 표시
    dropzone.innerHTML = `
      <div class="file-info" style="display: flex; align-items: center; gap: 10px;">
        <span class="file-icon" style="font-size: 2rem;">📄</span>
        <div>
          <div class="file-name">${file.name}</div>
          <div class="file-size">${formatBytes(file.size)}</div>
        </div>
      </div>
    `;
  } else {
    dropzone.textContent = "여기에 파일을 드래그하거나 클릭하여 업로드하세요.";
  }
}

// dropzone 클릭 시 파일 선택창 열기
dropzone.addEventListener("click", () => {
  fileInput.click();
});

// 파일이 dropzone 위에 있을 때 스타일 변경
dropzone.addEventListener("dragover", (e) => {
  e.preventDefault();
  dropzone.classList.add("dragover");
});

dropzone.addEventListener("dragleave", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");
});

// 파일 드롭 시 input에 파일 설정 및 미리보기 업데이트
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("dragover");

  // 드롭된 파일 중 첫 번째 파일만 사용하도록 설정
  const dt = new DataTransfer();
  dt.items.add(e.dataTransfer.files[0]);
  fileInput.files = dt.files;

  showUploadedFile();
});

// 파일 선택 시 미리보기 업데이트
fileInput.addEventListener("change", showUploadedFile);

// 업로드 및 디컴파일 요청
document.getElementById("confirmUpload").addEventListener("click", function () {
  if (!fileInput.files.length) {
    alert("바이너리 파일을 선택해 주세요.");
    return;
  }

  // 업로드 섹션 숨기고 진행중 메시지 표시
  document.getElementById("upload-section").style.display = "none";
  document.getElementById("processing-section").style.display = "flex";

  const file = fileInput.files[0];
  const formData = new FormData();
  formData.append("file", file);

  // /api/decompile 엔드포인트로 파일 전송 (백엔드에서 디컴파일 수행)
  fetch("/api/decompile", {
    method: "POST",
    body: formData,
  })
    .then((response) => response.json())
    .then((data) => {
      window.decompiledCode = data.decompiledCode;

      // 진행중 섹션 숨기고 분석 옵션 선택 섹션 표시
      document.getElementById("processing-section").style.display = "none";
      document.getElementById("action-selection").style.display = "block";
    })
    .catch((err) => {
      console.error(err);
      alert("디컴파일 중 오류가 발생했습니다.");
      document.getElementById("processing-section").style.display = "none";
      document.getElementById("upload-section").style.display = "block";
    });
});

// CodeQL 분석 선택
document.getElementById("runCodeQL").addEventListener("click", function () {
  fetch("/api/codeql", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ code: window.decompiledCode }),
  })
    .then((response) => response.json())
    .then((data) => {
      // 분석 결과 표시
      document.getElementById("action-selection").style.display = "none";
      document.getElementById("result-section").style.display = "block";
      document.getElementById("analysisResult").textContent = JSON.stringify(
        data,
        null,
        2
      );
      window.generatedCode = data.generatedCode;
    })
    .catch((err) => {
      console.error(err);
      alert("CodeQL 분석 중 오류가 발생했습니다.");
    });
});

// 퍼징 실행 선택
document.getElementById("runFuzzing").addEventListener("click", function () {
  fetch("/api/fuzzing", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ code: window.decompiledCode }),
  })
    .then((response) => response.json())
    .then((data) => {
      // 분석 결과 표시
      document.getElementById("action-selection").style.display = "none";
      document.getElementById("result-section").style.display = "block";
      document.getElementById("analysisResult").textContent = JSON.stringify(
        data,
        null,
        2
      );
      window.generatedCode = data.generatedCode;
    })
    .catch((err) => {
      console.error(err);
      alert("퍼징 실행 중 오류가 발생했습니다.");
    });
});

// 생성된 코드 다운로드
document
  .getElementById("downloadResult")
  .addEventListener("click", function () {
    if (!window.generatedCode) {
      alert("다운로드할 코드가 없습니다.");
      return;
    }

    const blob = new Blob([window.generatedCode], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "generated_code.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });
