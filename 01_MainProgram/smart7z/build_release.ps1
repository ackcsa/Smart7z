[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+(?:\.\d+)?$')]
    [string]$Version = '1.0.0',

    [string]$PythonExe = '',

    [string]$InnoSetupCompiler = ''
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$SourceDir = [IO.Path]::GetFullPath($PSScriptRoot)
$WorkspaceDir = [IO.Path]::GetFullPath(
    (Split-Path -Parent (Split-Path -Parent $SourceDir))
)
$BuildDir = Join-Path $SourceDir 'build'
$WorkDir = Join-Path $BuildDir 'pyinstaller-work'
$PyInstallerDist = Join-Path $BuildDir 'pyinstaller-dist'
$BaseAppDir = Join-Path $PyInstallerDist 'Smart7z'
$ReleaseDir = Join-Path $SourceDir 'release'
$VenvDir = Join-Path $SourceDir '.build-venv'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
$PortableName = "Smart7z-$Version-portable-windows-x64"
$PortableDir = Join-Path $ReleaseDir $PortableName
$PortableZip = Join-Path $ReleaseDir "$PortableName.zip"
$InstallerBaseName = "Smart7z-$Version-setup-windows-x64"
$InstallerPath = Join-Path $ReleaseDir "$InstallerBaseName.exe"
$SourcePackageName = "Smart7z-$Version-source"
$SourcePackageRoot = Join-Path $BuildDir 'source-package'
$SourcePackageDir = Join-Path $SourcePackageRoot $SourcePackageName
$SourceZip = Join-Path $ReleaseDir "$SourcePackageName.zip"
$BundledPython = Join-Path $SourceDir '.build-tools\python312\python.exe'

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )

    $parentPath = [IO.Path]::GetFullPath($Parent).TrimEnd('\')
    $childPath = [IO.Path]::GetFullPath($Child)
    $prefix = $parentPath + '\'
    if (-not $childPath.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to modify path outside build root: $childPath"
    }
}

function Remove-BuildPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-ChildPath -Parent $SourceDir -Child $Path
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -and
            ($item.LinkType -or $item.Target)
        ) {
            throw "Refusing to recursively remove a reparse point: $Path"
        }
        Remove-Item -LiteralPath $Path -Recurse -Force
    }
}

function Copy-FirstExistingLicense {
    param(
        [Parameter(Mandatory = $true)][string[]]$Candidates,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    foreach ($candidate in $Candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            Copy-Item -LiteralPath $candidate -Destination $Destination -Force
            return $true
        }
    }
    return $false
}

$OriginalLocation = Get-Location
$OriginalTclLibrary = [Environment]::GetEnvironmentVariable('TCL_LIBRARY', 'Process')
$OriginalTkLibrary = [Environment]::GetEnvironmentVariable('TK_LIBRARY', 'Process')

try {
    if (-not $PythonExe) {
        $pythonCandidates = @($BundledPython)
        foreach ($commandName in @('python', 'py')) {
            $pythonCommand = Get-Command $commandName -ErrorAction SilentlyContinue
            if ($pythonCommand) {
                $pythonCandidates += $pythonCommand.Source
            }
        }
        foreach ($candidate in ($pythonCandidates | Select-Object -Unique)) {
            if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
                continue
            }
            try {
                $candidateArchitecture = & $candidate -c "import struct; print(struct.calcsize('P') * 8)" 2>$null
                if ($LASTEXITCODE -eq 0 -and $candidateArchitecture.Trim() -eq '64') {
                    $PythonExe = $candidate
                    break
                }
            } catch {
                continue
            }
        }
    }
    if (-not $PythonExe -or -not (Test-Path -LiteralPath $PythonExe -PathType Leaf)) {
        throw 'A working 64-bit Python 3.10+ executable is required. Pass -PythonExe explicitly.'
    }

    $PythonExe = [IO.Path]::GetFullPath($PythonExe)
    $pythonArchitecture = & $PythonExe -c "import struct; print(struct.calcsize('P') * 8)"
    if ($LASTEXITCODE -ne 0 -or $pythonArchitecture.Trim() -ne '64') {
        throw "The release must be built with 64-bit Python. Found: $pythonArchitecture"
    }

    # Relative Tcl paths avoid Windows redirected-folder aliases while the
    # selected runtime remains the process working directory.
    $PythonRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PythonExe))
    Set-Location -LiteralPath $PythonRoot
    if (Test-Path -LiteralPath (Join-Path $PythonRoot 'tcl\tcl8.6\init.tcl')) {
        $env:TCL_LIBRARY = 'tcl/tcl8.6'
        $env:TK_LIBRARY = 'tcl/tk8.6'
    }

    $tkVersion = & $PythonExe -c "import tkinter; t = tkinter.Tcl(); print(t.eval('info patchlevel'))"
    if ($LASTEXITCODE -ne 0 -or -not $tkVersion.Trim()) {
        throw 'The selected Python runtime does not have a working Tcl/Tk installation.'
    }

    $expectedBase = $PythonRoot.TrimEnd('\')
    $venvValid = $false
    if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
        try {
            $venvBase = (& $VenvPython -c "import sys; print(sys.base_prefix)" 2>$null).Trim()
            $venvValid = (
                $LASTEXITCODE -eq 0 -and
                $venvBase.Equals($expectedBase, [StringComparison]::OrdinalIgnoreCase)
            )
        } catch {
            $venvValid = $false
        }
    }

    if (-not $venvValid -and (Test-Path -LiteralPath $VenvDir -PathType Container)) {
        Write-Host 'Repairing relocated build environment...'
        & $PythonExe -m venv --upgrade $VenvDir
        if ($LASTEXITCODE -eq 0) {
            try {
                $venvBase = (& $VenvPython -c "import sys; print(sys.base_prefix)" 2>$null).Trim()
                $venvValid = (
                    $LASTEXITCODE -eq 0 -and
                    $venvBase.Equals($expectedBase, [StringComparison]::OrdinalIgnoreCase)
                )
            } catch {
                $venvValid = $false
            }
        }
        if (-not $venvValid) {
            Remove-BuildPath -Path $VenvDir
        }
    }

    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        Write-Host 'Creating isolated build environment...'
        & $PythonExe -m venv $VenvDir
        if ($LASTEXITCODE -ne 0) { throw 'Could not create the build environment.' }
    }

    $venvTkVersion = & $VenvPython -c "import tkinter; t = tkinter.Tcl(); print(t.eval('info patchlevel'))"
    if ($LASTEXITCODE -ne 0 -or -not $venvTkVersion.Trim()) {
        throw 'The isolated build environment cannot initialize Tcl/Tk.'
    }

    $dependencyProbe = "from importlib.metadata import version; expected=(('PyInstaller','6.21.0'),('pyinstaller-hooks-contrib','2026.6'),('Pillow','12.3.0'),('tkinterdnd2','0.4.3')); raise SystemExit(0 if all(version(name)==wanted for name,wanted in expected) else 1)"
    & $VenvPython -c $dependencyProbe
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Installing build dependencies...'
        & $VenvPython -m pip install --disable-pip-version-check -r (Join-Path $SourceDir 'requirements-build.txt')
        if ($LASTEXITCODE -ne 0) { throw 'Could not install build dependencies.' }
    } else {
        Write-Host 'Build dependencies already match the locked versions.'
    }

    $passwordSeed = Get-Content -LiteralPath (Join-Path $SourceDir 'resources\code.txt') -Raw -Encoding UTF8
    if (-not [String]::IsNullOrWhiteSpace($passwordSeed)) {
        throw 'resources\code.txt must be empty before release packaging.'
    }
    $releaseConfig = Get-Content -LiteralPath (Join-Path $SourceDir 'resources\smart7z_config.json') -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($releaseConfig.cleanup_policy -ne 'keep' -or $releaseConfig.del_archive -ne $false) {
        throw 'Release configuration must default to cleanup_policy=keep and del_archive=false.'
    }

if (-not $InnoSetupCompiler) {
    $programFilesX86 = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFilesX86
    )
    $compilerCandidates = @(
        $env:INNO_SETUP_COMPILER,
        (Join-Path $SourceDir '.build-tools\inno\ISCC.exe'),
        (Join-Path $SourceDir '.build-tools\inno\app\ISCC.exe'),
        (Join-Path $programFilesX86 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
    )
    $InnoSetupCompiler = $compilerCandidates |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
        Select-Object -First 1
}
if (-not $InnoSetupCompiler -or -not (Test-Path -LiteralPath $InnoSetupCompiler -PathType Leaf)) {
    throw 'Inno Setup 6 compiler (ISCC.exe) is required. Pass -InnoSetupCompiler explicitly.'
}

Write-Host 'Generating application icon and Windows version metadata...'
& $VenvPython (Join-Path $SourceDir 'build_assets\generate_icon.py')
if ($LASTEXITCODE -ne 0) { throw 'Could not generate the application icon.' }

New-Item -ItemType Directory -Path $BuildDir -Force | Out-Null
$parts = @($Version.Split('.') | ForEach-Object { [int]$_ })
while ($parts.Count -lt 4) { $parts += 0 }
$versionTuple = '(' + (($parts | Select-Object -First 4) -join ', ') + ')'
$versionTemplate = Get-Content -LiteralPath (Join-Path $SourceDir 'smart7z_version_info.txt.in') -Raw -Encoding UTF8
$versionMetadata = $versionTemplate.Replace('__VERSION_TUPLE__', $versionTuple).Replace('__VERSION__', $Version)
$versionFile = Join-Path $BuildDir 'smart7z_version_info.txt'
[IO.File]::WriteAllText($versionFile, $versionMetadata, [Text.UTF8Encoding]::new($false))

Remove-BuildPath -Path $WorkDir
Remove-BuildPath -Path $PyInstallerDist
Remove-BuildPath -Path $PortableDir
Remove-BuildPath -Path $SourcePackageRoot
foreach ($artifact in @($PortableZip, $InstallerPath, $SourceZip)) {
    if (Test-Path -LiteralPath $artifact) {
        Assert-ChildPath -Parent $SourceDir -Child $artifact
        Remove-Item -LiteralPath $artifact -Force
    }
}
New-Item -ItemType Directory -Path $ReleaseDir -Force | Out-Null

$env:SMART7Z_DIST_NAME = 'Smart7z'
$env:SMART7Z_VERSION_FILE = $versionFile
try {
    Write-Host 'Building Smart7z.exe...'
    $pyInstallerArgs = @(
        '-m', 'PyInstaller',
        '--noconfirm',
        '--clean',
        '--distpath', $PyInstallerDist,
        '--workpath', $WorkDir,
        (Join-Path $SourceDir 'smart7z.spec')
    )
    & $VenvPython @pyInstallerArgs
    if ($LASTEXITCODE -ne 0) { throw 'PyInstaller failed.' }
} finally {
    Remove-Item Env:SMART7Z_DIST_NAME -ErrorAction SilentlyContinue
    Remove-Item Env:SMART7Z_VERSION_FILE -ErrorAction SilentlyContinue
}

if (-not (Test-Path -LiteralPath (Join-Path $BaseAppDir 'Smart7z.exe') -PathType Leaf)) {
    throw 'PyInstaller completed without producing Smart7z.exe.'
}

$SevenZipDir = @(
    (Join-Path $SourceDir '.build-tools\7zip'),
    (Join-Path $env:ProgramFiles '7-Zip'),
    (Join-Path ${env:ProgramFiles(x86)} '7-Zip')
) | Where-Object {
    $_ -and
    (Test-Path -LiteralPath (Join-Path $_ '7z.exe') -PathType Leaf) -and
    (Test-Path -LiteralPath (Join-Path $_ '7z.dll') -PathType Leaf) -and
    (Test-Path -LiteralPath (Join-Path $_ 'License.txt') -PathType Leaf)
} | Select-Object -First 1
if (-not $SevenZipDir) {
    throw 'A complete 7-Zip distribution (7z.exe, 7z.dll, License.txt) is required.'
}
$SevenZipExe = Join-Path $SevenZipDir '7z.exe'
$SevenZipDll = Join-Path $SevenZipDir '7z.dll'
$SevenZipLicense = Join-Path $SevenZipDir 'License.txt'
foreach ($required in @($SevenZipExe, $SevenZipDll, $SevenZipLicense)) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "Required 7-Zip distribution file is missing: $required"
    }
}

Write-Host 'Assembling shared application files...'
Copy-Item -LiteralPath $SevenZipExe -Destination (Join-Path $BaseAppDir '7z.exe') -Force
Copy-Item -LiteralPath $SevenZipDll -Destination (Join-Path $BaseAppDir '7z.dll') -Force
Copy-Item -LiteralPath $SevenZipLicense -Destination (Join-Path $BaseAppDir '7-Zip-License.txt') -Force
Copy-Item -LiteralPath (Join-Path $SourceDir 'resources\code.txt') -Destination (Join-Path $BaseAppDir 'code.txt') -Force
Copy-Item -LiteralPath (Join-Path $WorkspaceDir 'smart7z_user_manual .html') -Destination (Join-Path $BaseAppDir 'Smart7z-User-Manual.html') -Force
Copy-Item -LiteralPath (Join-Path $SourceDir 'THIRD_PARTY_NOTICES.txt') -Destination (Join-Path $BaseAppDir 'THIRD_PARTY_NOTICES.txt') -Force

$installedReadme = (Get-Content -LiteralPath (Join-Path $SourceDir 'release_readme_installed.txt') -Raw -Encoding UTF8).Replace('__VERSION__', $Version)
[IO.File]::WriteAllText(
    (Join-Path $BaseAppDir 'README.txt'),
    $installedReadme,
    [Text.UTF8Encoding]::new($true)
)

$LicenseDir = Join-Path $BaseAppDir 'licenses'
New-Item -ItemType Directory -Path $LicenseDir -Force | Out-Null
$basePrefix = (& $VenvPython -c "import sys; print(sys.base_prefix)").Trim()
$sitePackages = (& $VenvPython -c "import sysconfig; print(sysconfig.get_path('purelib'))").Trim()

[void](Copy-FirstExistingLicense -Candidates @(
    (Join-Path $basePrefix 'LICENSE.txt'),
    (Join-Path $basePrefix 'LICENSE')
) -Destination (Join-Path $LicenseDir 'Python-LICENSE.txt'))
[void](Copy-FirstExistingLicense -Candidates @(
    (Join-Path $basePrefix 'tcl\tk8.6\license.terms'),
    (Join-Path $basePrefix 'tcl\tk8.6\license.terms.txt')
) -Destination (Join-Path $LicenseDir 'Tcl-Tk-license.terms'))
[void](Copy-FirstExistingLicense -Candidates @(
    (Join-Path $sitePackages 'pyinstaller-6.21.0.dist-info\licenses\COPYING.txt'),
    (Join-Path $sitePackages 'PyInstaller\COPYING.txt'),
    (Join-Path $sitePackages 'PyInstaller\COPYING')
) -Destination (Join-Path $LicenseDir 'PyInstaller-COPYING.txt'))
[void](Copy-FirstExistingLicense -Candidates @(
    (Join-Path $sitePackages 'pyinstaller_hooks_contrib-2026.6.dist-info\licenses\LICENSE'),
    (Join-Path $sitePackages 'pyinstaller_hooks_contrib-2026.6.dist-info\LICENSE')
) -Destination (Join-Path $LicenseDir 'PyInstaller-hooks-contrib-LICENSE.txt'))

$dndLicense = Get-ChildItem -LiteralPath $sitePackages -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.FullName -match 'tkinterdnd2|tkdnd' -and
        $_.Name -match '^(LICENSE|LICENSE\.txt|license\.terms|COPYING)$'
    } |
    Select-Object -First 1
if ($dndLicense) {
    Copy-Item -LiteralPath $dndLicense.FullName -Destination (Join-Path $LicenseDir 'TkinterDnD2-LICENSE.txt') -Force
}
$requiredLicenses = @(
    'Python-LICENSE.txt',
    'Tcl-Tk-license.terms',
    'PyInstaller-COPYING.txt',
    'PyInstaller-hooks-contrib-LICENSE.txt',
    'TkinterDnD2-LICENSE.txt'
)
foreach ($licenseName in $requiredLicenses) {
    if (-not (Test-Path -LiteralPath (Join-Path $LicenseDir $licenseName) -PathType Leaf)) {
        throw "Required third-party license is missing: $licenseName"
    }
}

foreach ($requiredName in @('Smart7z.exe', '7z.exe', '7z.dll', '7-Zip-License.txt', 'code.txt', 'Smart7z-User-Manual.html', 'README.txt', 'THIRD_PARTY_NOTICES.txt')) {
    if (-not (Test-Path -LiteralPath (Join-Path $BaseAppDir $requiredName) -PathType Leaf)) {
        throw "Shared application file is missing: $requiredName"
    }
}
if ((Get-Item -LiteralPath (Join-Path $BaseAppDir 'code.txt')).Length -ne 0) {
    throw 'Packaged password candidate file must be empty.'
}
foreach ($forbiddenName in @('portable.flag', 'smart7z_config.json', 'recovery-v1.json', 'recovery-v1.json.lock')) {
    if (Test-Path -LiteralPath (Join-Path $BaseAppDir $forbiddenName)) {
        throw "Installed application staging contains forbidden runtime state: $forbiddenName"
    }
}

Write-Host 'Creating portable release...'
Copy-Item -LiteralPath $BaseAppDir -Destination $PortableDir -Recurse
New-Item -ItemType File -Path (Join-Path $PortableDir 'portable.flag') -Force | Out-Null
$portableReadme = (Get-Content -LiteralPath (Join-Path $SourceDir 'release_readme_portable.txt') -Raw -Encoding UTF8).Replace('__VERSION__', $Version)
[IO.File]::WriteAllText(
    (Join-Path $PortableDir 'README.txt'),
    $portableReadme,
    [Text.UTF8Encoding]::new($true)
)
Compress-Archive -LiteralPath $PortableDir -DestinationPath $PortableZip -CompressionLevel Optimal
if (-not (Test-Path -LiteralPath (Join-Path $PortableDir 'portable.flag') -PathType Leaf)) {
    throw 'Portable release is missing portable.flag.'
}

Write-Host 'Creating installer release...'
$innoArgs = @(
    "/DMyAppVersion=$Version",
    "/DSourceDir=$BaseAppDir",
    "/DOutputDir=$ReleaseDir",
    "/DInstallerBaseName=$InstallerBaseName",
    (Join-Path $SourceDir 'smart7z_installer.iss')
)
& $InnoSetupCompiler @innoArgs
if ($LASTEXITCODE -ne 0) { throw 'Inno Setup compiler failed.' }
if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
    throw 'Inno Setup completed without producing the installer.'
}

Write-Host 'Creating source release...'
New-Item -ItemType Directory -Path $SourcePackageDir -Force | Out-Null
$sourceRootFiles = @(
    'build_release.ps1',
    'release_readme_installed.txt',
    'release_readme_portable.txt',
    'release_readme_source.txt',
    'requirements-build.txt',
    'smart7z.spec',
    'smart7z_installer.iss',
    'smart7z_version_info.txt.in',
    'THIRD_PARTY_NOTICES.txt'
)
$sourceRootFiles += Get-ChildItem -LiteralPath $SourceDir -File -Filter '*.py' | ForEach-Object Name
foreach ($sourceName in ($sourceRootFiles | Select-Object -Unique)) {
    $sourcePath = Join-Path $SourceDir $sourceName
    if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
        throw "Source package input is missing: $sourceName"
    }
    Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $SourcePackageDir $sourceName) -Force
}

foreach ($directoryName in @('tests', 'build_assets', 'resources')) {
    New-Item -ItemType Directory -Path (Join-Path $SourcePackageDir $directoryName) -Force | Out-Null
}
Get-ChildItem -LiteralPath (Join-Path $SourceDir 'tests') -File -Filter '*.py' |
    Copy-Item -Destination (Join-Path $SourcePackageDir 'tests') -Force
foreach ($assetName in @('ChineseSimplified.isl', 'generate_icon.py', 'smart7z.ico')) {
    Copy-Item -LiteralPath (Join-Path $SourceDir "build_assets\$assetName") -Destination (Join-Path $SourcePackageDir "build_assets\$assetName") -Force
}
foreach ($resourceName in @('code.txt', 'smart7z_config.json')) {
    Copy-Item -LiteralPath (Join-Path $SourceDir "resources\$resourceName") -Destination (Join-Path $SourcePackageDir "resources\$resourceName") -Force
}
Copy-Item -LiteralPath (Join-Path $WorkspaceDir 'smart7z_user_manual .html') -Destination (Join-Path $SourcePackageDir 'Smart7z-User-Manual.html') -Force
$sourceReadme = (Get-Content -LiteralPath (Join-Path $SourceDir 'release_readme_source.txt') -Raw -Encoding UTF8).Replace('__VERSION__', $Version)
[IO.File]::WriteAllText(
    (Join-Path $SourcePackageDir 'README.txt'),
    $sourceReadme,
    [Text.UTF8Encoding]::new($true)
)
Compress-Archive -LiteralPath $SourcePackageDir -DestinationPath $SourceZip -CompressionLevel Optimal

$hashLines = @(
    (Get-FileHash -LiteralPath $PortableZip -Algorithm SHA256 | ForEach-Object { "$($_.Hash)  $([IO.Path]::GetFileName($_.Path))" }),
    (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256 | ForEach-Object { "$($_.Hash)  $([IO.Path]::GetFileName($_.Path))" }),
    (Get-FileHash -LiteralPath $SourceZip -Algorithm SHA256 | ForEach-Object { "$($_.Hash)  $([IO.Path]::GetFileName($_.Path))" })
)
$hashPath = Join-Path $ReleaseDir 'SHA256SUMS.txt'
Set-Content -LiteralPath $hashPath -Value $hashLines -Encoding ASCII

$portableSize = [Math]::Round((Get-Item -LiteralPath $PortableZip).Length / 1MB, 2)
$installerSize = [Math]::Round((Get-Item -LiteralPath $InstallerPath).Length / 1MB, 2)
$sourceSize = [Math]::Round((Get-Item -LiteralPath $SourceZip).Length / 1MB, 2)
Write-Host ''
Write-Host "Portable:  $PortableZip ($portableSize MiB)"
Write-Host "Installer: $InstallerPath ($installerSize MiB)"
Write-Host "Source:    $SourceZip ($sourceSize MiB)"
Write-Host "Checksums: $hashPath"
} finally {
    Set-Location -LiteralPath $OriginalLocation
    [Environment]::SetEnvironmentVariable('TCL_LIBRARY', $OriginalTclLibrary, 'Process')
    [Environment]::SetEnvironmentVariable('TK_LIBRARY', $OriginalTkLibrary, 'Process')
}
