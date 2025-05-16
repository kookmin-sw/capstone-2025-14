// CSRF 토큰 가져오기
function getCSRFToken() {
  return document.cookie
    .split("; ")
    .find((row) => row.startsWith("csrftoken="))
    ?.split("=")[1];
}

// dropzone과 파일 입력 요소 참조
const dropzone = document.getElementById("dropzone");
const fileInput = document.getElementById("fileInput");

// 파일 정보 미리보기 업데이트 함수
function showUploadedFile() {
  if (fileInput.files.length > 0) {
    const file = fileInput.files[0];
    window.uploadedFileName = file.name;

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

  // /capstone/api/decompile 엔드포인트로 파일 전송 (백엔드에서 디컴파일 수행)
  fetch("/capstone/api/decompile/", {
    method: "POST",
    body: formData,
    headers: {
      "X-CSRFToken": getCSRFToken(), // CSRF 토큰 포함
    },
  })
    .then((response) => response.json())
    .then((data) => {
      if (data.error) {
        alert(data.error);
        document.getElementById("upload-section").style.display = "block";
        document.getElementById("processing-section").style.display = "none";
        return;
      }
      window.decompiledCode = data.decompiledCode;

      // 진행중 섹션 숨기고 결과 섹션 표시
      document.getElementById("processing-section").style.display = "none";
      const analysisResult = document.getElementById("analysisResult");
      analysisResult.textContent = data.decompiledCode;
      // Prism.js로 문법 하이라이팅 적용
      Prism.highlightElement(analysisResult);
      document.getElementById("result-section").style.display = "block";
      document.getElementById("upload-section").style.display = "none";
      if (data.downloadUrl) {
        //document.getElementById("downloadLink").href = data.downloadUrl;
      }
    })
    .catch((err) => {
      console.error(err);
      alert("디컴파일 중 오류가 발생했습니다.");
      document.getElementById("processing-section").style.display = "none";
      document.getElementById("upload-section").style.display = "block";
    });
});

function clearHighlightsForSource(source) {
  document.querySelectorAll(`.line-highlight[data-source="${source}"]`)
    .forEach(el => {
      if (el._tooltip) el._tooltip.dispose();
      el.remove();
    });
}

// === CodeQL 버튼 비활성화/활성화 추가 ===
function runCodeQL() {
  if (!fileInput.files.length) {
    alert('먼저 파일을 업로드하세요.');
    return;
  }
  // 버튼 참조 및 비활성화
  const codeqlBtn = document.querySelector('button[onclick="runCodeQL()"]');
  if (codeqlBtn) codeqlBtn.disabled = true;

  clearHighlightsForSource('codeql');
  const fd = new FormData();
  fd.append('file', fileInput.files[0]);

  fetch(`/capstone/api/codeql/${window.uploadedFileName}/`, {
    method: 'POST',
    headers: { 'X-CSRFToken': getCSRFToken() },
    body: fd
  })
    .then(res => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    })
    .then(data => {
      const lines = Array.from(new Set(
        data
          .filter(item => item['Start line'] && item.Severity)
          .map(item => parseInt(item['Start line'], 10))
          .filter(n => !isNaN(n))
      )).sort((a, b) => a - b);

      const pre = document.getElementById('source-code');
      pre.setAttribute('data-line', lines.join(','));
      Prism.highlightElement(pre.querySelector('code'));

      setTimeout(() => {
        lines.forEach(line => {
          const info = data.find(d => +d['Start line'] === line);
          if (!info || !info.Severity) {
            const maybeHl = document.querySelector(`.line-highlight[data-range="${line}"]`);
            if (maybeHl) maybeHl.remove();
            return;
          }
          const sev = info.Severity.toLowerCase();
          let bgColor;
          switch (sev) {
            case 'critical': bgColor = 'rgba(255,   0,   0, 0.3)'; break;
            case 'high': bgColor = 'rgba(255, 165,   0, 0.3)'; break;
            case 'warning': bgColor = 'rgba(255, 255,   0, 0.3)'; break;
            case 'low': bgColor = 'rgba(  0, 128,   0, 0.3)'; break;
            default: bgColor = 'rgba(255, 255, 255, 0.3)';
          }
          const hl = document.querySelector(`.line-highlight[data-range="${line}"]`);
          if (!hl) return;
          hl.style.setProperty('background-color', bgColor, 'important');
          hl.dataset.source = 'codeql';
          const name = info.Name || '';
          const desc = info.Description || '';
          const msg = info.Message || '';
          const html = `
          <div class="tooltip-content">
            <div class="tooltip-section"><div class="tooltip-label">Name</div><div class="tooltip-desc">${name}</div></div>
            <hr class="tooltip-divider" />
            <div class="tooltip-section"><div class="tooltip-label">Description</div><div class="tooltip-desc">${desc}</div></div>
            <hr class="tooltip-divider" />
            <div class="tooltip-section"><div class="tooltip-label">Message</div><div class="tooltip-desc">${msg}</div></div>
          </div>
        `;
          hl.removeAttribute('title');
          hl.setAttribute('data-bs-html', 'true');
          hl.setAttribute('data-bs-original-title', html);
          hl.setAttribute('data-bs-toggle', 'tooltip');
          hl.setAttribute('data-bs-placement', 'top');
          hl.setAttribute('data-bs-container', 'body');
          new bootstrap.Tooltip(hl, { container: 'body', trigger: 'hover', html: true });
        });
      }, 0);
    })
    .catch(err => {
      console.error(err);
      alert('CodeQL 분석 중 오류가 발생했습니다.');
    })
    .finally(() => {
      if (codeqlBtn) codeqlBtn.disabled = false;
    });
}

function downloadCode() {
  // <pre> 안의 <code> 요소를 찾아서 그 안의 텍스트를 가져옴
  const codeElement = document.querySelector("#analysisResult");
  const codeText = codeElement ? codeElement.innerText.trim() : "";
  const originalName = window.uploadedFileName || "code";
  const downloadFileName = originalName + ".c";
  // 텍스트 파일(blob) 생성 및 다운로드 실행
  const blob = new Blob([codeText], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = downloadFileName; // 다운로드할 파일명 지정
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// === Taint 버튼 비활성화/활성화 추가 ===
function runTaint() {
  if (!fileInput.files.length) {
    alert('먼저 파일을 업로드하세요.');
    return;
  }
  const taintBtn = document.querySelector('button[onclick="runTaint()"]');
  if (taintBtn) taintBtn.disabled = true;

  clearHighlightsForSource('codeql');
  clearHighlightsForSource('taint');
  const fd = new FormData();
  fd.append('file', fileInput.files[0]);

  fetch(`/capstone/api/taint/${window.uploadedFileName}/`, {
    method: 'POST',
    headers: { 'X-CSRFToken': getCSRFToken() },
    body: fd
  })
    .then(res => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    })
    .then(data => {
      const lines = Array.from(new Set(
        data
          .filter(item => item['Start line'] && item.Severity)
          .map(item => parseInt(item['Start line'], 10))
          .filter(n => !isNaN(n))
      )).sort((a, b) => a - b);

      const pre = document.getElementById('source-code');
      pre.setAttribute('data-line', lines.join(','));
      Prism.highlightElement(pre.querySelector('code'));

      setTimeout(() => {
        lines.forEach(line => {
          const info = data.find(d => +d['Start line'] === line);
          if (!info || !info.Severity) {
            const maybeHl = document.querySelector(`.line-highlight[data-range="${line}"]`);
            if (maybeHl) maybeHl.remove();
            return;
          }
          const hl = document.querySelector(`.line-highlight[data-range="${line}"]`);
          if (!hl) return;
          hl.style.setProperty('background-color', 'rgba(255,   0,   0, 0.3)', 'important');
          hl.dataset.source = 'taint';
          const name = info.Name || '';
          const desc = info.Description || '';
          const msg = info.Message || '';
          const html = `
          <div class="tooltip-content">
            <div class="tooltip-section"><div class="tooltip-label">Name</div><div class="tooltip-desc">${name}</div></div>
            <hr class="tooltip-divider" />
            <div class="tooltip-section"><div class="tooltip-label">Description</div><div class="tooltip-desc">${desc}</div></div>
            <hr class="tooltip-divider" />
            <div class="tooltip-section"><div class="tooltip-label">Message</div><div class="tooltip-desc">${msg}</div></div>
          </div>
        `;
          hl.removeAttribute('title');
          hl.setAttribute('data-bs-html', 'true');
          hl.setAttribute('data-bs-original-title', html);
          hl.setAttribute('data-bs-toggle', 'tooltip');
          hl.setAttribute('data-bs-placement', 'top');
          hl.setAttribute('data-bs-container', 'body');
          new bootstrap.Tooltip(hl, { container: 'body', trigger: 'hover', html: true });
        });
      }, 0);
    })
    .catch(err => {
      console.error(err);
      alert('Taint 분석 중 오류가 발생했습니다.');
    })
    .finally(() => {
      if (taintBtn) taintBtn.disabled = false;
    });
}

document.addEventListener("DOMContentLoaded", () => {
  const title = document.getElementById("title");
  const uploadSection = document.getElementById("upload-section");

  setTimeout(() => {
    title.style.top = "0";
    title.style.opacity = "1";
  }, 500);

  setTimeout(() => {
    uploadSection.style.opacity = "1";
  }, 1500);
});
