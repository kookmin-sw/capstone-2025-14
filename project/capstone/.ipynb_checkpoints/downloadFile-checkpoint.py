import os
from django.http import HttpResponse, Http404
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings

@csrf_exempt
def download_decompiled_file(request, filename):
    # MEDIA_ROOT/uploads 폴더의 절대 경로 구성 (/app/idea101/media/uploads/filename.c)
    file_path = os.path.join(settings.MEDIA_ROOT, "uploads", filename)
    
    if os.path.exists(file_path):
        # 이진 모드로 파일을 읽어 다운로드 응답 생성
        with open(file_path, "rb") as f:
            response = HttpResponse(f.read(), content_type="text/plain")
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            return response
    else:
        raise Http404("File not found")
