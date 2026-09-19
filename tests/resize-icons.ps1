$src = "C:\Users\dell\.gemini\antigravity\brain\17c0ff64-d048-4b70-b15f-453c98da4b6d\scamshield_logo_1789820587961.jpg"
$assetsDir = "c:\Users\dell\Documents\scam-shield-extension\assets"
$iconsDir = "c:\Users\dell\Documents\scam-shield-extension\icons"

if (!(Test-Path $assetsDir)) {
    New-Item -ItemType Directory -Force -Path $assetsDir
}

Copy-Item $src (Join-Path $assetsDir "logo.jpg") -Force

Add-Type -AssemblyName System.Drawing

$img = [System.Drawing.Image]::FromFile($src)

$sizes = @(16, 48, 128)
foreach ($s in $sizes) {
    $bmp = New-Object System.Drawing.Bitmap($s, $s)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.DrawImage($img, 0, 0, $s, $s)
    $outPath = Join-Path $iconsDir ("icon" + $s + ".png")
    $bmp.Save($outPath, [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose()
    $bmp.Dispose()
    Write-Host "Created icon$s.png"
}
$img.Dispose()
