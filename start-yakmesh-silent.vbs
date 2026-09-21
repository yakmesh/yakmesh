' YakMesh silent launcher — runs the node with no console window.
' Output goes to yakmesh-node.log in this directory. Double-click to start.
' To watch live: run VIEW-YAKMESH-LOG.bat or open yakmesh-node.log.

Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")

dir = fso.GetParentFolderName(WScript.ScriptFullName)
sh.CurrentDirectory = dir

' Per-node settings (env vars only — yakmesh.config.js must stay identical)
' Bootstrap peer — LAN seed node (override by setting YAKMESH_BOOTSTRAP in the system env)
if sh.Environment("PROCESS")("YAKMESH_BOOTSTRAP") = "" then
    sh.Environment("PROCESS")("YAKMESH_BOOTSTRAP") = "ws://192.168.1.172:9080"
end if
sh.Environment("PROCESS")("YAKMESH_DATA_DIR") = sh.ExpandEnvironmentStrings("%LOCALAPPDATA%") & "\yakmesh-data"

' 0 = hidden window, False = don't wait
sh.Run "cmd.exe /c node server\index.js >> yakmesh-node.log 2>&1", 0, False
