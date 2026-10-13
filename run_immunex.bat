@echo off
title IMMUNEX Security Platform
echo ========================================================
echo   Starting IMMUNEX Autonomous Security Pipeline
echo   Access Dashboard at: http://127.0.0.1:8000
echo ========================================================
set KMP_DUPLICATE_LIB_OK=TRUE
set OMP_NUM_THREADS=1
F:\anaconda3\python.exe -m uvicorn local_runtime:app --host 127.0.0.1 --port 8000
pause
