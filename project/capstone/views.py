from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
from .decompile import *
from .downloadFile import download_decompiled_file
import os

@ensure_csrf_cookie
def index(request):
    file_path = os.getcwd()+'/capstone/templates/index.html'
    return render(request, file_path)

def decompiled(request):
    response = decompile(request)
    print("Response from decompile:", response)
    return response

def download(request):
    return download_decompiled_file(request)