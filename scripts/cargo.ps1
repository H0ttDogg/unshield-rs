param([Parameter(ValueFromRemainingArguments=$true)][string[]]$RustArgs)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
if (Test-Path -LiteralPath "$projectRoot/.tools/cargo/bin/cargo.exe") {
    $env:RUSTUP_HOME = "$projectRoot/.tools/rustup"
    $env:CARGO_HOME = "$projectRoot/.tools/cargo"
    & "$projectRoot/.tools/cargo/bin/cargo.exe" @RustArgs
} else { & cargo @RustArgs }
exit $LASTEXITCODE
