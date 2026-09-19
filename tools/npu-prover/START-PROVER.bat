@echo off
REM YakMesh NPU Execution Prover — serves /npu/proof on 127.0.0.1:9997
REM Same contract as rust-embed; ONNX Runtime + DirectML backend.
cd /d "%~dp0\..\.."
start "yakmesh-npu-prover" /min node tools\npu-prover\prover.mjs --port 9997
