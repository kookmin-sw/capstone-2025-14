from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
from .decompile import *
from .downloadFile import download_decompiled_file
import os

@ensure_csrf_cookie
def index(request):
    # 템플릿 이름만 사용
    return render(request, 'index.html')

def decompiled(request):
    response = decompile(request)
    print("Response from decompile:", response)
    return response

# filename 매개변수 추가
def download(request, filename):
    return download_decompiled_file(request, filename)