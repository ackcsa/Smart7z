[CmdletBinding()]
param(
    [ValidatePattern('^\d+\.\d+\.\d+(?:\.\d+)?$')]
    [string]$Version = '1.0.2',

    [string]$PythonExe = '',

    [string]$InnoSetupCompiler = '',

<<<<<<< HEAD
    [string]$QtSourceCache = '',

    [string]$CSharpCompiler = ''
=======
    [string]$QtSourceCache = ''
>>>>>>> origin/main
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
$ReleaseResourcesDir = Join-Path $BuildDir 'release-resources'
$ReleasePasswordFile = Join-Path $ReleaseResourcesDir 'code.txt'
$ReleaseConfigFile = Join-Path $ReleaseResourcesDir 'smart7z_config.json'
$ReleaseConfigGeneratorPath = Join-Path $ReleaseResourcesDir 'generate_release_config.py'
$QtSourceExtractorPath = Join-Path $ReleaseResourcesDir 'extract_qt_source.py'
<<<<<<< HEAD
$ShellLauncherSource = Join-Path $SourceDir 'shell_launcher.cs'
$ShellLauncherVersionSource = Join-Path $ReleaseResourcesDir 'shell_launcher_version.cs'
$ShellLauncherName = 'Smart7zShell.exe'
=======
>>>>>>> origin/main
$BundledPython = Join-Path $SourceDir '.build-tools\python312\python.exe'
$QtBaseArchiveName = 'qtbase-everywhere-src-6.11.1.tar.xz'
$PySideArchiveName = 'pyside-setup-everywhere-src-6.11.1.tar.xz'
$QtBaseExpectedSha256 = 'D9594A31228AA23AD6B531719A29B45F0F3989FE6C136D45767EA179F233C1AC'
$PySideExpectedSha256 = '6FFD9835BB0DD2C56F061D62F1616BB1707CFC0202B80E3165D6BE087F3965E2'
$ReleaseLicenseDir = Join-Path $ReleaseResourcesDir 'licenses'
$ReleaseCorrespondingSourceDir = Join-Path $ReleaseResourcesDir 'corresponding-source'
$ReleaseSourceManifest = Join-Path $ReleaseLicenseDir 'Qt-PySide6-source-manifest.json'
$ReleaseSourceNotice = Join-Path $ReleaseResourcesDir 'Qt-PySide6-CORRESPONDING_SOURCE.txt'
$VcRuntimeNoticeName = 'Microsoft-Visual-Cpp-Runtime-NOTICE.txt'
$VcRuntimeManifestName = 'Microsoft-Visual-Cpp-Runtime-manifest.json'
$VcRuntimeLicenseName = 'Microsoft-Visual-Cpp-Runtime-2015-2022-License.docx'
$VcRuntimeNoticePath = Join-Path $SourceDir $VcRuntimeNoticeName
$VcRuntimeLicensePath = Join-Path $SourceDir $VcRuntimeLicenseName
$VcRuntimeLicenseSha256 = 'F1E3D56CEB2AD68AAE0711B910375009E651AC5530FA0760F0DEA6E81E54FAE1'
$ReleaseVcRuntimeManifest = Join-Path $ReleaseLicenseDir $VcRuntimeManifestName
$ForbiddenLegacyNames = @(
    'dWlfYXBw',
    'dGVzdF91aV9saWZlY3ljbGU=',
    'dGtpbnRlcmRuZDI=',
    'X3RraW50ZXI=',
    'dGtpbnRlcg==',
    'dGNs',
    'dGs='
) | ForEach-Object {
    [Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($_))
}
$ForbiddenLegacyTextPattern = (
    '(?i)(?<![A-Za-z0-9_])(?:' +
    (($ForbiddenLegacyNames | ForEach-Object { [regex]::Escape($_) }) -join '|') +
    ')(?![A-Za-z0-9_])'
)

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

function Resolve-QtSourceCache {
    param([string]$RequestedPath)

    $candidates = @()
    if ($RequestedPath) {
        $candidates = @($RequestedPath)
    } else {
        $candidates = @(
            (Join-Path $SourceDir '.license-cache'),
            (Join-Path $SourceDir '.build-tools\qt-source')
        )
    }

    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        $candidatePath = $candidate
        if (-not [IO.Path]::IsPathRooted($candidatePath)) {
            $candidatePath = Join-Path $SourceDir $candidatePath
        }
        $candidatePath = [IO.Path]::GetFullPath($candidatePath)
        if (
            (Test-Path -LiteralPath (Join-Path $candidatePath $QtBaseArchiveName) -PathType Leaf) -and
            (Test-Path -LiteralPath (Join-Path $candidatePath $PySideArchiveName) -PathType Leaf)
        ) {
            return $candidatePath
        }
    }

    $requestedText = if ($RequestedPath) { " Requested: $RequestedPath" } else { '' }
    throw (
        'A complete Qt/PySide source cache is required.' +
        " Expected $QtBaseArchiveName and $PySideArchiveName under .license-cache or .build-tools\\qt-source." +
        $requestedText
    )
}

function Assert-VerifiedQtSourceArchive {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$ExpectedSha256
    )

    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
        throw "Qt/PySide source archive is missing: $ArchivePath"
    }
    $actualSha256 = (Get-FileHash -LiteralPath $ArchivePath -Algorithm SHA256).Hash.ToUpperInvariant()
    if ($actualSha256 -ne $ExpectedSha256) {
        throw "Qt/PySide source archive SHA256 mismatch: $ArchivePath (expected $ExpectedSha256, got $actualSha256)"
    }
}

function Normalize-ZipEntryName {
    param([Parameter(Mandatory = $true)][string]$Name)

    return $Name.Replace('\', '/').TrimStart('/')
}

function Test-ZipEntrySuffix {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Suffix
    )

    $normalizedName = (Normalize-ZipEntryName -Name $Name).ToLowerInvariant()
    $normalizedSuffix = (Normalize-ZipEntryName -Name $Suffix).ToLowerInvariant()
    return (
        $normalizedName -eq $normalizedSuffix -or
        $normalizedName.EndsWith('/' + $normalizedSuffix, [StringComparison]::Ordinal)
    )
}

function Test-ForbiddenPackagePath {
    param([Parameter(Mandatory = $true)][string]$Name)

    foreach ($segment in (Normalize-ZipEntryName -Name $Name).Split('/')) {
        $lower = $segment.ToLowerInvariant()
        foreach ($legacyName in $ForbiddenLegacyNames) {
            $escapedName = [regex]::Escape($legacyName)
            if ($lower -match "^$escapedName(?:[._-].*)?$") {
                return $true
            }
            if (
                ($legacyName -eq $ForbiddenLegacyNames[5] -or
                 $legacyName -eq $ForbiddenLegacyNames[6]) -and
                $lower -match "^$escapedName[0-9._-].*$"
            ) {
                return $true
            }
        }
    }
    return $false
}

function Test-AuditedTextEntry {
    param([Parameter(Mandatory = $true)][string]$Name)

    $extension = [IO.Path]::GetExtension($Name).ToLowerInvariant()
    return $extension -in @(
        '.cfg', '.html', '.htm', '.ini', '.iss', '.json', '.md',
        '.ps1', '.psm1', '.py', '.pyw', '.spec', '.txt', '.toml',
        '.yaml', '.yml'
    )
}

function Read-ZipEntryText {
    param([Parameter(Mandatory = $true)]$Entry)

    $stream = $Entry.Open()
    try {
        $reader = [IO.StreamReader]::new($stream, [Text.Encoding]::UTF8, $true)
        try {
            return $reader.ReadToEnd()
        } finally {
            $reader.Dispose()
        }
    } finally {
        $stream.Dispose()
    }
}

function Assert-ReleaseArchive {
    param(
        [Parameter(Mandatory = $true)][string]$ArchivePath,
        [Parameter(Mandatory = $true)][string]$PasswordEntrySuffix,
        [string]$ConfigEntrySuffix = '',
        [string[]]$RequiredEntries = @(),
        [string[]]$AllowedLegacyTextEntries = @(),
        [string[]]$TextAuditExcludedPrefixes = @(),
        [switch]$AuditText
    )

    if (-not (Test-Path -LiteralPath $ArchivePath -PathType Leaf)) {
        throw "Release archive is missing: $ArchivePath"
    }

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $archive = [IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $entryNames = @()
        $passwordEntries = @()
        $configEntries = @()
        $violations = @()

        foreach ($entry in $archive.Entries) {
            $normalized = Normalize-ZipEntryName -Name $entry.FullName
            $entryNames += $normalized
            if (Test-ForbiddenPackagePath -Name $normalized) {
                $violations += $normalized
            }
            if (Test-ZipEntrySuffix -Name $normalized -Suffix $PasswordEntrySuffix) {
                $passwordEntries += $entry
            }
            if (
                $ConfigEntrySuffix -and
                (Test-ZipEntrySuffix -Name $normalized -Suffix $ConfigEntrySuffix)
            ) {
                $configEntries += $entry
            }

            if ($normalized.EndsWith('.zip', [StringComparison]::OrdinalIgnoreCase)) {
                $nestedStream = $entry.Open()
                $memory = [IO.MemoryStream]::new()
                try {
                    $nestedStream.CopyTo($memory)
                    $memory.Position = 0
                    $nestedArchive = [IO.Compression.ZipArchive]::new(
                        $memory,
                        [IO.Compression.ZipArchiveMode]::Read,
                        $true
                    )
                    try {
                        foreach ($nestedEntry in $nestedArchive.Entries) {
                            $nestedName = Normalize-ZipEntryName -Name $nestedEntry.FullName
                            if (Test-ForbiddenPackagePath -Name $nestedName) {
                                $violations += "$normalized!$nestedName"
                            }
                        }
                    } finally {
                        $nestedArchive.Dispose()
                    }
                } finally {
                    $nestedStream.Dispose()
                    $memory.Dispose()
                }
            }

            $textAuditExcluded = $false
            foreach ($excludedPrefix in $TextAuditExcludedPrefixes) {
                $normalizedPrefix = (Normalize-ZipEntryName -Name $excludedPrefix).TrimEnd('/')
                if (
                    $normalized -eq $normalizedPrefix -or
                    $normalized.EndsWith('/' + $normalizedPrefix, [StringComparison]::OrdinalIgnoreCase) -or
                    $normalized.IndexOf('/' + $normalizedPrefix + '/', [StringComparison]::OrdinalIgnoreCase) -ge 0
                ) {
                    $textAuditExcluded = $true
                    break
                }
            }
            if ($AuditText -and -not $textAuditExcluded -and (Test-AuditedTextEntry -Name $normalized)) {
                $allowLegacyText = $false
                foreach ($allowed in $AllowedLegacyTextEntries) {
                    if (Test-ZipEntrySuffix -Name $normalized -Suffix $allowed) {
                        $allowLegacyText = $true
                        break
                    }
                }
                if (-not $allowLegacyText) {
                    $text = Read-ZipEntryText -Entry $entry
                    if ($text -match $ForbiddenLegacyTextPattern) {
                        $violations += "$normalized (text)"
                    }
                }
            }
        }

        if ($violations.Count -gt 0) {
            $details = ($violations | Select-Object -Unique | ForEach-Object { "  $_" }) -join [Environment]::NewLine
            throw "Release archive contains forbidden legacy UI content: $ArchivePath$([Environment]::NewLine)$details"
        }

        foreach ($required in ($RequiredEntries | Select-Object -Unique)) {
            $found = $false
            foreach ($entryName in $entryNames) {
                if (Test-ZipEntrySuffix -Name $entryName -Suffix $required) {
                    $found = $true
                    break
                }
            }
            if (-not $found) {
                throw "Release archive is missing required entry '$required': $ArchivePath"
            }
        }

        if ($passwordEntries.Count -ne 1) {
            throw "Release archive must contain exactly one '$PasswordEntrySuffix': $ArchivePath"
        }
        if ($passwordEntries[0].Length -ne 0) {
            throw "Release archive contains a non-empty password candidate file: $ArchivePath"
        }

        if ($ConfigEntrySuffix) {
            if ($configEntries.Count -ne 1) {
                throw "Release archive must contain exactly one '$ConfigEntrySuffix': $ArchivePath"
            }
            $packagedConfig = (Read-ZipEntryText -Entry $configEntries[0]) | ConvertFrom-Json
            if (
                $packagedConfig.cleanup_policy -ne 'keep' -or
                $packagedConfig.del_archive -ne $false
            ) {
                throw "Release archive contains an unsafe default configuration: $ArchivePath"
            }
        }
    } finally {
        $archive.Dispose()
    }

    Write-Host "Audited release archive: $ArchivePath"
}

function Assert-MinimalQtRuntime {
    param([Parameter(Mandatory = $true)][string]$Root)

    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        throw "Qt runtime root is missing: $Root"
    }

    $pysideRoots = @(
        Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force |
            Where-Object { $_.Name -ceq 'PySide6' }
    )
    if ($pysideRoots.Count -ne 1) {
        throw "Expected exactly one PySide6 runtime directory under $Root; found $($pysideRoots.Count)."
    }

    $rootPath = [IO.Path]::GetFullPath((Get-Item -LiteralPath $Root).FullName)
    $rootPrefix = $rootPath
    if (-not $rootPrefix.EndsWith('\')) {
        $rootPrefix += '\'
    }
    $pysideRoot = [IO.Path]::GetFullPath($pysideRoots[0].FullName)
    $pysidePrefix = $pysideRoot
    if (-not $pysidePrefix.EndsWith('\')) {
        $pysidePrefix += '\'
    }
    $allowedBindings = @('QtCore.pyd', 'QtGui.pyd', 'QtWidgets.pyd')
    $allowedLibraries = @('Qt6Core.dll', 'Qt6Gui.dll', 'Qt6Widgets.dll')
    $allowedPlugins = @(
        'plugins/imageformats/qico.dll',
        'plugins/platforms/qwindows.dll',
        'plugins/styles/qmodernwindowsstyle.dll'
    )
    $canonicalVcRuntimeFiles = @(
        'MSVCP140.dll',
        'MSVCP140_1.dll',
        'MSVCP140_2.dll',
        'VCRUNTIME140.dll',
        'VCRUNTIME140_1.dll'
    )
    $expectedVcRuntimeVersion = '14.44.35211.0'
    $vcRuntimePattern = '(?i)^(?:concrt140|msvcp140(?:_1|_2|_atomic_wait|_codecvt_ids)?|vcruntime140(?:_1)?)\.dll$'
    $forbiddenQtAuxiliaryFiles = @('opengl32sw.dll')
    $requiredFiles = @($allowedBindings + $allowedLibraries + $allowedPlugins)
    $violations = @()

    $internalRoot = [IO.Path]::GetFullPath((Split-Path -Parent $pysideRoot))
    foreach ($runtimeName in $canonicalVcRuntimeFiles) {
        $runtimePath = Join-Path $internalRoot $runtimeName
        if (-not (Test-Path -LiteralPath $runtimePath -PathType Leaf)) {
            $violations += "missing: $runtimeName"
            continue
        }
        $runtimeVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($runtimePath).FileVersion
        if ($runtimeVersion -ne $expectedVcRuntimeVersion) {
            $violations += "unexpected version: $runtimeName ($runtimeVersion)"
        }
    }

    foreach ($relative in $requiredFiles) {
        $requiredPath = Join-Path $pysideRoot ($relative.Replace('/', '\'))
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            $violations += "missing: $relative"
        }
    }

    foreach ($file in (Get-ChildItem -LiteralPath $Root -File -Recurse -Force)) {
        $filePath = [IO.Path]::GetFullPath($file.FullName)
        $insidePySide = $filePath.StartsWith(
            $pysidePrefix,
            [StringComparison]::OrdinalIgnoreCase
        )
        $relative = if ($insidePySide) {
            $filePath.Substring($pysidePrefix.Length).Replace('\', '/')
        } else {
            $filePath.Substring($rootPrefix.Length).Replace('\', '/')
        }

        if ($file.Name -match $vcRuntimePattern) {
            $fileDirectory = [IO.Path]::GetFullPath($file.DirectoryName)
            if (
                -not $fileDirectory.Equals($internalRoot, [StringComparison]::OrdinalIgnoreCase) -or
                $canonicalVcRuntimeFiles -notcontains $file.Name
            ) {
                $violations += $relative
            }
            continue
        }

        if ($file.Name -match '(?i)^Qt.*\.pyd$') {
            if (-not $insidePySide -or $allowedBindings -notcontains $file.Name) {
                $violations += $relative
            }
            continue
        }
        if ($file.Name -match '(?i)^Qt6.*\.dll$') {
            if (-not $insidePySide -or $allowedLibraries -notcontains $file.Name) {
                $violations += $relative
            }
            continue
        }
        if (-not $insidePySide) {
            continue
        }
        if ($forbiddenQtAuxiliaryFiles -contains $file.Name.ToLowerInvariant()) {
            $violations += $relative
            continue
        }
        if ($relative.StartsWith('qml/', [StringComparison]::OrdinalIgnoreCase)) {
            $violations += $relative
            continue
        }
        if ($relative.StartsWith('translations/', [StringComparison]::OrdinalIgnoreCase)) {
            $violations += $relative
            continue
        }
        if (
            $relative.StartsWith('plugins/', [StringComparison]::OrdinalIgnoreCase) -and
            $allowedPlugins -notcontains $relative
        ) {
            $violations += $relative
        }
    }

    if ($violations.Count -gt 0) {
        $details = ($violations | Select-Object -Unique | Sort-Object | ForEach-Object { "  $_" }) -join [Environment]::NewLine
        throw "PyInstaller output exceeds the licensed minimal Qt runtime:$([Environment]::NewLine)$details"
    }

    Write-Host "Audited minimal Qt runtime: $Root"
}

$OriginalLocation = Get-Location

try {
    if ($InnoSetupCompiler -and -not [IO.Path]::IsPathRooted($InnoSetupCompiler)) {
        $InnoSetupCompiler = Join-Path $SourceDir $InnoSetupCompiler
    }
    if ($InnoSetupCompiler) {
        $InnoSetupCompiler = [IO.Path]::GetFullPath($InnoSetupCompiler)
    }
<<<<<<< HEAD
    if ($CSharpCompiler -and -not [IO.Path]::IsPathRooted($CSharpCompiler)) {
        $CSharpCompiler = Join-Path $SourceDir $CSharpCompiler
    }
    if ($CSharpCompiler) {
        $CSharpCompiler = [IO.Path]::GetFullPath($CSharpCompiler)
    }
=======
>>>>>>> origin/main

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

    $PythonRoot = [IO.Path]::GetFullPath((Split-Path -Parent $PythonExe))
    Set-Location -LiteralPath $PythonRoot

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

    $dependencyProbe = "from importlib.metadata import version; expected=(('PyInstaller','6.21.0'),('pyinstaller-hooks-contrib','2026.6'),('Pillow','12.3.0'),('PySide6','6.11.1'),('PySide6_Essentials','6.11.1'),('PySide6_Addons','6.11.1'),('shiboken6','6.11.1'),('altgraph','0.17.5'),('packaging','26.3'),('pefile','2024.8.26'),('pywin32-ctypes','0.2.3'),('setuptools','83.0.0')); raise SystemExit(0 if all(version(name)==wanted for name,wanted in expected) else 1)"
    & $VenvPython -c $dependencyProbe
    if ($LASTEXITCODE -ne 0) {
        Write-Host 'Installing build dependencies...'
        & $VenvPython -m pip install --disable-pip-version-check -r (Join-Path $SourceDir 'requirements-build.txt')
        if ($LASTEXITCODE -ne 0) { throw 'Could not install build dependencies.' }
    } else {
        Write-Host 'Build dependencies already match the locked versions.'
    }

    $QtSourceCache = Resolve-QtSourceCache -RequestedPath $QtSourceCache
    $QtBaseArchive = Join-Path $QtSourceCache $QtBaseArchiveName
    $PySideArchive = Join-Path $QtSourceCache $PySideArchiveName
    Assert-VerifiedQtSourceArchive -ArchivePath $QtBaseArchive -ExpectedSha256 $QtBaseExpectedSha256
    Assert-VerifiedQtSourceArchive -ArchivePath $PySideArchive -ExpectedSha256 $PySideExpectedSha256
    Write-Host "Verified Qt/PySide source cache: $QtSourceCache"

if (-not $InnoSetupCompiler) {
    $programFilesX86 = [Environment]::GetFolderPath(
        [Environment+SpecialFolder]::ProgramFilesX86
    )
    $compilerCandidates = @(
        $env:INNO_SETUP_COMPILER,
        (Join-Path $SourceDir '.build-tools\inno\ISCC.exe'),
        (Join-Path $SourceDir '.build-tools\inno\app\ISCC.exe'),
        (Join-Path $programFilesX86 'Inno Setup 7\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 7\ISCC.exe'),
        (Join-Path $programFilesX86 'Inno Setup 6\ISCC.exe'),
        (Join-Path $env:ProgramFiles 'Inno Setup 6\ISCC.exe')
    )
    $InnoSetupCompiler = $compilerCandidates |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
        Select-Object -First 1
}
if (-not $InnoSetupCompiler -or -not (Test-Path -LiteralPath $InnoSetupCompiler -PathType Leaf)) {
    throw 'Inno Setup compiler (ISCC.exe) is required. Pass -InnoSetupCompiler explicitly.'
}

if (-not $CSharpCompiler) {
    $csharpCandidates = @(
        (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'),
        (Get-Command 'csc.exe' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1)
    )
    $CSharpCompiler = $csharpCandidates |
        Where-Object { $_ -and (Test-Path -LiteralPath $_ -PathType Leaf) } |
        Select-Object -First 1
}
if (-not $CSharpCompiler -or -not (Test-Path -LiteralPath $CSharpCompiler -PathType Leaf)) {
    throw 'The 64-bit .NET Framework C# compiler is required. Pass -CSharpCompiler explicitly.'
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
Remove-BuildPath -Path $ReleaseResourcesDir
foreach ($artifact in @($PortableZip, $InstallerPath, $SourceZip)) {
    if (Test-Path -LiteralPath $artifact) {
        Assert-ChildPath -Parent $SourceDir -Child $artifact
        Remove-Item -LiteralPath $artifact -Force
    }
}
New-Item -ItemType Directory -Path $ReleaseDir -Force | Out-Null

Write-Host 'Preparing sanitized release resources...'
New-Item -ItemType Directory -Path $ReleaseResourcesDir -Force | Out-Null
[IO.File]::WriteAllBytes($ReleasePasswordFile, [byte[]]::new(0))
$releaseConfigGenerator = @'
import json
import sys
from pathlib import Path

source_dir = Path(sys.argv[1])
destination = Path(sys.argv[2])
sys.path.insert(0, str(source_dir))
from config import DEFAULT_CONFIG

config = dict(DEFAULT_CONFIG)
config["cleanup_policy"] = "keep"
config["del_archive"] = False
destination.write_text(
    json.dumps(config, indent=4, ensure_ascii=False) + "\n",
    encoding="utf-8",
)
'@
[IO.File]::WriteAllText($ReleaseConfigGeneratorPath, $releaseConfigGenerator, [Text.UTF8Encoding]::new($false))
& $VenvPython $ReleaseConfigGeneratorPath $SourceDir $ReleaseConfigFile
if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $ReleaseConfigGeneratorPath -Force -ErrorAction SilentlyContinue
    throw 'Could not generate sanitized release configuration.'
}
Remove-Item -LiteralPath $ReleaseConfigGeneratorPath -Force
$releaseConfig = Get-Content -LiteralPath $ReleaseConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
if (
    $releaseConfig.cleanup_policy -ne 'keep' -or
    $releaseConfig.del_archive -ne $false -or
    $releaseConfig.steganographier_compat_mode -ne $true
) {
    throw 'Sanitized release configuration is not safe.'
}
if ((Get-Item -LiteralPath $ReleasePasswordFile).Length -ne 0) {
    throw 'Sanitized release password candidate file must be empty.'
}

Write-Host 'Extracting verified Qt/PySide licenses and corresponding source...'
$licenseAndSourceExtractor = @'
import hashlib
import json
import shutil
import sys
import tarfile
from pathlib import Path, PurePosixPath

qt_archive = Path(sys.argv[1])
pyside_archive = Path(sys.argv[2])
destination = Path(sys.argv[3])
manifest_path = Path(sys.argv[4])

license_dir = destination / "licenses"
source_dir = destination / "corresponding-source"
license_dir.mkdir(parents=True, exist_ok=True)
source_dir.mkdir(parents=True, exist_ok=True)

def safe_parts(name: str):
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise RuntimeError(f"Unsafe path in source archive: {name}")
    return path.parts

def extract_archive(archive_path: Path):
    with tarfile.open(archive_path, "r:xz") as archive:
        members = archive.getmembers()
        if not members:
            raise RuntimeError(f"Source archive is empty: {archive_path}")
        roots = {safe_parts(member.name)[0] for member in members}
        if len(roots) != 1:
            raise RuntimeError(f"Source archive must have one top-level directory: {archive_path}")
        root_name = next(iter(roots))
        output_root = source_dir / root_name
        if output_root.exists():
            shutil.rmtree(output_root)
        for member in members:
            parts = safe_parts(member.name)
            target = source_dir.joinpath(*parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"Could not read source archive member: {member.name}")
                with extracted, target.open("wb") as output:
                    shutil.copyfileobj(extracted, output)
            else:
                raise RuntimeError(f"Unsupported source archive member type: {member.name}")
        return root_name

def copy_license(archive_path: Path, archive_root: str, source_name: str, destination_name: str):
    member_name = f"{archive_root}/LICENSES/{source_name}"
    with tarfile.open(archive_path, "r:xz") as archive:
        try:
            member = archive.getmember(member_name)
        except KeyError as exc:
            raise RuntimeError(f"Required license body is missing from {archive_path}: {member_name}") from exc
        if not member.isfile():
            raise RuntimeError(f"Required license entry is not a regular file: {member_name}")
        extracted = archive.extractfile(member)
        if extracted is None:
            raise RuntimeError(f"Could not read license body: {member_name}")
        with extracted, (license_dir / destination_name).open("wb") as output:
            shutil.copyfileobj(extracted, output)

qt_root = extract_archive(qt_archive)
pyside_root = extract_archive(pyside_archive)
for source_name, destination_name in (
    ("LGPL-3.0-only.txt", "Qt-LGPL-3.0-only.txt"),
    ("GPL-3.0-only.txt", "Qt-GPL-3.0-only.txt"),
    ("Qt-GPL-exception-1.0.txt", "Qt-GPL-exception-1.0.txt"),
):
    copy_license(qt_archive, qt_root, source_name, destination_name)
for source_name, destination_name in (
    ("LGPL-3.0-only.txt", "PySide6-LGPL-3.0-only.txt"),
    ("GPL-3.0-only.txt", "PySide6-GPL-3.0-only.txt"),
    ("Qt-GPL-exception-1.0.txt", "PySide6-Qt-GPL-exception-1.0.txt"),
):
    copy_license(pyside_archive, pyside_root, source_name, destination_name)

manifest = {
    "qt_version": "6.11.1",
    "pyside6_version": "6.11.1",
    "shiboken6_version": "6.11.1",
    "components": ["QtBase", "PySide6", "Shiboken6"],
    "source_archives": [
        {
            "archive": qt_archive.name,
            "sha256": hashlib.sha256(qt_archive.read_bytes()).hexdigest().upper(),
            "source_path": f"corresponding-source/{qt_root}/",
        },
        {
            "archive": pyside_archive.name,
            "sha256": hashlib.sha256(pyside_archive.read_bytes()).hexdigest().upper(),
            "source_path": f"corresponding-source/{pyside_root}/",
        },
    ],
    "license_files": sorted(path.name for path in license_dir.glob("*.txt")),
}
manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
'@
[IO.File]::WriteAllText($QtSourceExtractorPath, $licenseAndSourceExtractor, [Text.UTF8Encoding]::new($false))
try {
    & $VenvPython $QtSourceExtractorPath $QtBaseArchive $PySideArchive $ReleaseResourcesDir $ReleaseSourceManifest
} finally {
    Remove-Item -LiteralPath $QtSourceExtractorPath -Force -ErrorAction SilentlyContinue
}
if ($LASTEXITCODE -ne 0) {
    throw 'Could not extract verified Qt/PySide license bodies and corresponding source.'
}
$vcRuntimeLicenseHash = (
    Get-FileHash -LiteralPath $VcRuntimeLicensePath -Algorithm SHA256
).Hash.ToUpperInvariant()
if ($vcRuntimeLicenseHash -ne $VcRuntimeLicenseSha256) {
    throw "Microsoft Visual C++ Runtime license hash mismatch: $vcRuntimeLicenseHash"
}
Copy-Item -LiteralPath $VcRuntimeLicensePath -Destination (Join-Path $ReleaseLicenseDir $VcRuntimeLicenseName) -Force

$sourceNotice = @"
Smart7z $Version Qt/PySide corresponding source notice
======================================================

Components covered by the accompanying license texts:
- QtBase 6.11.1
- PySide6 6.11.1
- Shiboken6 6.11.1

The matching corresponding source is shipped in the Smart7z-$Version-source.zip
release under corresponding-source/. It contains the extracted qtbase-everywhere-src-
6.11.1/ and pyside-setup-everywhere-src-6.11.1/ source trees. The exact archive
hashes and license-body provenance are recorded in licenses/Qt-PySide6-source-manifest.json.

The build used community PySide6/Shiboken6 wheels. The commercial license placeholder
is intentionally not used; the included license bodies came from the verified official
Qt and Qt for Python source archives listed in the manifest.
"@
[IO.File]::WriteAllText($ReleaseSourceNotice, $sourceNotice.TrimStart(), [Text.UTF8Encoding]::new($false))

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
Assert-MinimalQtRuntime -Root $BaseAppDir

$baseInternalDir = Join-Path $BaseAppDir '_internal'
$vcRuntimeNames = @(
    'MSVCP140.dll',
    'MSVCP140_1.dll',
    'MSVCP140_2.dll',
    'VCRUNTIME140.dll',
    'VCRUNTIME140_1.dll'
)
$vcRuntimeEntries = @(
    foreach ($runtimeName in $vcRuntimeNames) {
        $runtimePath = Join-Path $baseInternalDir $runtimeName
        $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($runtimePath)
        [ordered]@{
            file = $runtimeName
            file_version = $versionInfo.FileVersion
            sha256 = (Get-FileHash -LiteralPath $runtimePath -Algorithm SHA256).Hash
        }
    }
)
$vcRuntimeManifest = [ordered]@{
    component = 'Microsoft Visual C++ Runtime'
    architecture = 'x64'
    source_package = 'PySide6_Essentials==6.11.1 official wheel'
    canonical_directory = '_internal'
    selection_policy = 'smart7z.spec selects PySide6_Essentials wheel copies and removes package-local duplicates'
    files = $vcRuntimeEntries
}
[IO.File]::WriteAllText(
    $ReleaseVcRuntimeManifest,
    (($vcRuntimeManifest | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
    [Text.UTF8Encoding]::new($false)
)

Write-Host 'Building lightweight Explorer launcher...'
$assemblyVersionParts = @($Version.Split('.'))
while ($assemblyVersionParts.Count -lt 4) {
    $assemblyVersionParts += '0'
}
$assemblyVersion = $assemblyVersionParts -join '.'
$shellVersionMetadata = @"
using System.Reflection;

[assembly: AssemblyVersion("$assemblyVersion")]
[assembly: AssemblyFileVersion("$assemblyVersion")]
[assembly: AssemblyInformationalVersion("$Version")]
"@
[IO.File]::WriteAllText(
    $ShellLauncherVersionSource,
    $shellVersionMetadata.TrimStart(),
    [Text.UTF8Encoding]::new($false)
)
$shellLauncherPath = Join-Path $BaseAppDir $ShellLauncherName
$csharpArgs = @(
    '/nologo',
    '/target:winexe',
    '/platform:x64',
    '/optimize+',
    '/reference:System.dll',
    '/reference:System.Core.dll',
    '/reference:System.Runtime.Serialization.dll',
    '/reference:System.Windows.Forms.dll',
    "/win32icon:$(Join-Path $SourceDir 'build_assets\smart7z.ico')",
    "/out:$shellLauncherPath",
    $ShellLauncherSource,
    $ShellLauncherVersionSource
)
& $CSharpCompiler @csharpArgs
if ($LASTEXITCODE -ne 0) {
    throw 'Could not build the lightweight Explorer launcher.'
}
if (-not (Test-Path -LiteralPath $shellLauncherPath -PathType Leaf)) {
    throw 'C# compilation completed without producing Smart7zShell.exe.'
}
$shellVersionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($shellLauncherPath)
if ($shellVersionInfo.FileVersion -ne $assemblyVersion) {
    throw "Smart7zShell.exe version mismatch: $($shellVersionInfo.FileVersion)"
}
Assert-MinimalQtRuntime -Root $BaseAppDir

$baseInternalDir = Join-Path $BaseAppDir '_internal'
$vcRuntimeNames = @(
    'MSVCP140.dll',
    'MSVCP140_1.dll',
    'MSVCP140_2.dll',
    'VCRUNTIME140.dll',
    'VCRUNTIME140_1.dll'
)
$vcRuntimeEntries = @(
    foreach ($runtimeName in $vcRuntimeNames) {
        $runtimePath = Join-Path $baseInternalDir $runtimeName
        $versionInfo = [Diagnostics.FileVersionInfo]::GetVersionInfo($runtimePath)
        [ordered]@{
            file = $runtimeName
            file_version = $versionInfo.FileVersion
            sha256 = (Get-FileHash -LiteralPath $runtimePath -Algorithm SHA256).Hash
        }
    }
)
$vcRuntimeManifest = [ordered]@{
    component = 'Microsoft Visual C++ Runtime'
    architecture = 'x64'
    source_package = 'PySide6_Essentials==6.11.1 official wheel'
    canonical_directory = '_internal'
    selection_policy = 'smart7z.spec selects PySide6_Essentials wheel copies and removes package-local duplicates'
    files = $vcRuntimeEntries
}
[IO.File]::WriteAllText(
    $ReleaseVcRuntimeManifest,
    (($vcRuntimeManifest | ConvertTo-Json -Depth 4) + [Environment]::NewLine),
    [Text.UTF8Encoding]::new($false)
)

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
<<<<<<< HEAD
Copy-Item -LiteralPath (Join-Path $SourceDir 'build_assets\smart7z.ico') -Destination (Join-Path $BaseAppDir 'smart7z.ico') -Force
=======
>>>>>>> origin/main
Copy-Item -LiteralPath $ReleasePasswordFile -Destination (Join-Path $BaseAppDir 'code.txt') -Force
Copy-Item -LiteralPath (Join-Path $WorkspaceDir 'smart7z_user_manual .html') -Destination (Join-Path $BaseAppDir 'Smart7z-User-Manual.html') -Force
Copy-Item -LiteralPath (Join-Path $SourceDir 'THIRD_PARTY_NOTICES.txt') -Destination (Join-Path $BaseAppDir 'THIRD_PARTY_NOTICES.txt') -Force
Copy-Item -LiteralPath $ReleaseSourceNotice -Destination (Join-Path $BaseAppDir 'Qt-PySide6-CORRESPONDING_SOURCE.txt') -Force
Copy-Item -LiteralPath $VcRuntimeNoticePath -Destination (Join-Path $BaseAppDir $VcRuntimeNoticeName) -Force

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
    (Join-Path $sitePackages 'pyinstaller-6.21.0.dist-info\licenses\COPYING.txt'),
    (Join-Path $sitePackages 'PyInstaller\COPYING.txt'),
    (Join-Path $sitePackages 'PyInstaller\COPYING')
) -Destination (Join-Path $LicenseDir 'PyInstaller-COPYING.txt'))
[void](Copy-FirstExistingLicense -Candidates @(
    (Join-Path $sitePackages 'pyinstaller_hooks_contrib-2026.6.dist-info\licenses\LICENSE'),
    (Join-Path $sitePackages 'pyinstaller_hooks_contrib-2026.6.dist-info\LICENSE')
) -Destination (Join-Path $LicenseDir 'PyInstaller-hooks-contrib-LICENSE.txt'))
$qtLicenseNames = @(
    'Qt-LGPL-3.0-only.txt',
    'Qt-GPL-3.0-only.txt',
    'Qt-GPL-exception-1.0.txt',
    'PySide6-LGPL-3.0-only.txt',
    'PySide6-GPL-3.0-only.txt',
    'PySide6-Qt-GPL-exception-1.0.txt',
    'Qt-PySide6-source-manifest.json'
)
foreach ($qtLicenseName in $qtLicenseNames) {
    $sourceLicense = Join-Path $ReleaseLicenseDir $qtLicenseName
    if (-not (Test-Path -LiteralPath $sourceLicense -PathType Leaf)) {
        throw "Verified Qt/PySide release material is missing: $qtLicenseName"
    }
    Copy-Item -LiteralPath $sourceLicense -Destination (Join-Path $LicenseDir $qtLicenseName) -Force
}
Copy-Item -LiteralPath $ReleaseVcRuntimeManifest -Destination (Join-Path $LicenseDir $VcRuntimeManifestName) -Force
Copy-Item -LiteralPath $VcRuntimeLicensePath -Destination (Join-Path $LicenseDir $VcRuntimeLicenseName) -Force
$requiredLicenses = @(
    'Python-LICENSE.txt',
    'PyInstaller-COPYING.txt',
    'PyInstaller-hooks-contrib-LICENSE.txt',
    'Qt-LGPL-3.0-only.txt',
    'Qt-GPL-3.0-only.txt',
    'Qt-GPL-exception-1.0.txt',
    'PySide6-LGPL-3.0-only.txt',
    'PySide6-GPL-3.0-only.txt',
    'PySide6-Qt-GPL-exception-1.0.txt',
    'Qt-PySide6-source-manifest.json',
    'Microsoft-Visual-Cpp-Runtime-manifest.json',
    'Microsoft-Visual-Cpp-Runtime-2015-2022-License.docx'
)
foreach ($licenseName in $requiredLicenses) {
    if (-not (Test-Path -LiteralPath (Join-Path $LicenseDir $licenseName) -PathType Leaf)) {
        throw "Required third-party license is missing: $licenseName"
    }
}

<<<<<<< HEAD
foreach ($requiredName in @('Smart7z.exe', 'Smart7zShell.exe', 'smart7z.ico', '7z.exe', '7z.dll', '7-Zip-License.txt', 'code.txt', 'Smart7z-User-Manual.html', 'README.txt', 'THIRD_PARTY_NOTICES.txt', 'Qt-PySide6-CORRESPONDING_SOURCE.txt', 'Microsoft-Visual-Cpp-Runtime-NOTICE.txt')) {
=======
foreach ($requiredName in @('Smart7z.exe', '7z.exe', '7z.dll', '7-Zip-License.txt', 'code.txt', 'Smart7z-User-Manual.html', 'README.txt', 'THIRD_PARTY_NOTICES.txt', 'Qt-PySide6-CORRESPONDING_SOURCE.txt', 'Microsoft-Visual-Cpp-Runtime-NOTICE.txt')) {
>>>>>>> origin/main
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
Assert-MinimalQtRuntime -Root $PortableDir
Assert-ReleaseArchive `
    -ArchivePath $PortableZip `
    -PasswordEntrySuffix 'code.txt' `
    -RequiredEntries @(
        'Smart7z.exe',
<<<<<<< HEAD
        'Smart7zShell.exe',
        'smart7z.ico',
=======
>>>>>>> origin/main
        'portable.flag',
        'THIRD_PARTY_NOTICES.txt',
        'Qt-PySide6-CORRESPONDING_SOURCE.txt',
        'Microsoft-Visual-Cpp-Runtime-NOTICE.txt',
        'licenses/Qt-LGPL-3.0-only.txt',
        'licenses/Qt-GPL-3.0-only.txt',
        'licenses/Qt-GPL-exception-1.0.txt',
        'licenses/PySide6-LGPL-3.0-only.txt',
        'licenses/PySide6-GPL-3.0-only.txt',
        'licenses/PySide6-Qt-GPL-exception-1.0.txt',
        'licenses/Qt-PySide6-source-manifest.json',
        'licenses/Microsoft-Visual-Cpp-Runtime-manifest.json',
        'licenses/Microsoft-Visual-Cpp-Runtime-2015-2022-License.docx'
    ) `
    -TextAuditExcludedPrefixes @('licenses/') `
    -AuditText

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
<<<<<<< HEAD
    'shell_launcher.cs',
=======
>>>>>>> origin/main
    'THIRD_PARTY_NOTICES.txt',
    'Microsoft-Visual-Cpp-Runtime-NOTICE.txt'
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
Copy-Item -LiteralPath $ReleaseLicenseDir -Destination (Join-Path $SourcePackageDir 'licenses') -Recurse -Force
Copy-Item -LiteralPath $ReleaseCorrespondingSourceDir -Destination (Join-Path $SourcePackageDir 'corresponding-source') -Recurse -Force
Get-ChildItem -LiteralPath (Join-Path $SourceDir 'tests') -File -Filter '*.py' |
    Copy-Item -Destination (Join-Path $SourcePackageDir 'tests') -Force
foreach ($assetName in @('ChineseSimplified.isl', 'generate_icon.py', 'smart7z.ico')) {
    Copy-Item -LiteralPath (Join-Path $SourceDir "build_assets\$assetName") -Destination (Join-Path $SourcePackageDir "build_assets\$assetName") -Force
}
foreach ($resourceName in @('code.txt', 'smart7z_config.json')) {
    $stagedResource = Join-Path $ReleaseResourcesDir $resourceName
    Copy-Item -LiteralPath $stagedResource -Destination (Join-Path $SourcePackageDir "resources\$resourceName") -Force
}
Copy-Item -LiteralPath (Join-Path $WorkspaceDir 'smart7z_user_manual .html') -Destination (Join-Path $SourcePackageDir 'Smart7z-User-Manual.html') -Force
Copy-Item -LiteralPath $ReleaseSourceNotice -Destination (Join-Path $SourcePackageDir 'Qt-PySide6-CORRESPONDING_SOURCE.txt') -Force
$sourceReadme = (Get-Content -LiteralPath (Join-Path $SourceDir 'release_readme_source.txt') -Raw -Encoding UTF8).Replace('__VERSION__', $Version)
[IO.File]::WriteAllText(
    (Join-Path $SourcePackageDir 'README.txt'),
    $sourceReadme,
    [Text.UTF8Encoding]::new($true)
)
Compress-Archive -LiteralPath $SourcePackageDir -DestinationPath $SourceZip -CompressionLevel Optimal

$requiredSourceEntries = @(
    'ui_qt.py',
<<<<<<< HEAD
    'launch_ipc.py',
    'runtime_ipc.py',
    'shell_launcher.cs',
=======
    'runtime_ipc.py',
>>>>>>> origin/main
    'tests/test_ui_runtime.py'
)
$requiredSourceEntries += Get-ChildItem -LiteralPath (Join-Path $SourceDir 'tests') -File |
    Where-Object { $_.Name -match '(?i)qt' } |
    ForEach-Object { "tests/$($_.Name)" }
$requiredSourceEntries += @(
    'licenses/Qt-LGPL-3.0-only.txt',
    'licenses/Qt-GPL-3.0-only.txt',
    'licenses/Qt-GPL-exception-1.0.txt',
    'licenses/PySide6-LGPL-3.0-only.txt',
    'licenses/PySide6-GPL-3.0-only.txt',
    'licenses/PySide6-Qt-GPL-exception-1.0.txt',
    'licenses/Qt-PySide6-source-manifest.json',
    'licenses/Microsoft-Visual-Cpp-Runtime-manifest.json',
    'licenses/Microsoft-Visual-Cpp-Runtime-2015-2022-License.docx',
    'corresponding-source/qtbase-everywhere-src-6.11.1/CMakeLists.txt',
    'corresponding-source/qtbase-everywhere-src-6.11.1/LICENSES/LGPL-3.0-only.txt',
    'corresponding-source/pyside-setup-everywhere-src-6.11.1/CMakeLists.txt',
    'corresponding-source/pyside-setup-everywhere-src-6.11.1/LICENSES/LGPL-3.0-only.txt',
    'Qt-PySide6-CORRESPONDING_SOURCE.txt',
    'Microsoft-Visual-Cpp-Runtime-NOTICE.txt'
)
Assert-ReleaseArchive `
    -ArchivePath $SourceZip `
    -PasswordEntrySuffix 'resources/code.txt' `
    -ConfigEntrySuffix 'resources/smart7z_config.json' `
    -RequiredEntries $requiredSourceEntries `
    -AllowedLegacyTextEntries @('build_release.ps1', 'smart7z.spec') `
    -TextAuditExcludedPrefixes @('corresponding-source/', 'licenses/') `
    -AuditText

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
}
