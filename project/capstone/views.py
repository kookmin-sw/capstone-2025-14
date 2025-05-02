from django.shortcuts import render
from django.views.decorators.csrf import ensure_csrf_cookie
from .decompile import *
from .downloadFile import download_decompiled_file
from .codeql_view import codeql_result
from .taint_view import taint_func
from config import *
@ensure_csrf_cookie
def index(request):
    return render(request, 'index.html')

def decompiled(request):
    response = decompile(request)
    print("Response from decompile:", response)
    return response

def download(request, filename):
    return download_decompiled_file(request, filename)

def codeql(request, filename):
    return codeql_result(request, filename)

def taint(request, filename):
    return taint_func(request, filename)