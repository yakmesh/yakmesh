@echo off
REM YakMesh NPU Execution Prover — serves /npu/proof on 127.0.0.1:9997
REM Same contract as rust-embed. Backend cascade: VitisAI (XDNA) ->
REM DML device_filter=npu -> DML gpu -> ORT cpu -> js-cpu (honest floor).
REM RyzenAI deployment dir on PATH so LoadLibrary finds the Vitis EP dlls.
REM Output goes to prover.log (on the share — readable for remote debug).
if exist "C:\Program Files\RyzenAI\1.7.0\deployment" set "PATH=C:\Program Files\RyzenAI\1.7.0\deployment;%PATH%"
cd /d "%~dp0\..\.."
echo === %DATE% %TIME% === >> tools\npu-prover\prover.log
start "yakmesh-npu-prover" /min cmd /c "node tools\npu-prover\prover.mjs --port 9997 >> tools\npu-prover\prover.log 2>&1"
