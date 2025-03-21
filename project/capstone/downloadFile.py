import os
import subprocess
import json
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

@csrf_exempt
def download_decompiled_file(request, filename):
    file_path = os.path.join("media/uploads", filename)

    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            response = HttpResponse(f.read(), content_type="text/plain")
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            return response

    return JsonResponse({"error": "File not found"}, status=404)
