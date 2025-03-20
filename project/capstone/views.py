from django.shortcuts import render
import os

def index(request):
    file_path = os.getcwd()+'/capstone/templates/index.html'
    return render(request, file_path)