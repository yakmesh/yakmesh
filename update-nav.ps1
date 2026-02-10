$files = Get-ChildItem "docs/*.html"
$count = 0
foreach ($file in $files) {
    $content = Get-Content $file.FullName -Raw -Encoding UTF8
    if (-not ($content -match 'gumba\.html')) {
        $old = '<li><a href="annex.html"><span>🌉</span> <span>ANNEX</span></a></li>
      <li><a href="yak-protocol.html">'
        $new = '<li><a href="annex.html"><span>🌉</span> <span>ANNEX</span></a></li>
      <li><a href="gumba.html"><span>🛕</span> <span>GUMBA</span></a></li>
      <li><a href="yak-protocol.html">'
        $content = $content.Replace($old, $new)
        [System.IO.File]::WriteAllText($file.FullName, $content)
        $count++
    }
}
Write-Host "Updated $count files"
