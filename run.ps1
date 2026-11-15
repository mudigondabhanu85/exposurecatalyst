<#
.SYNOPSIS
  ExposureCatalyst - start / update / restart the Docker deployment safely (Windows hosts; mirrors run.sh).

.DESCRIPTION
  .\run.ps1                 bring the app up, or apply changes since the last successful run and restart
  .\run.ps1 help            all subcommands

  Same safety model as run.sh: preflight, lock, change detection, :rollback image tags, database backup before
  migrations, health-gated success, automatic image rollback on failure (never an automatic database restore).
  Timestamped output to the console and logs\run.log. Secrets are never printed.
  Exit codes: 0 ok, 1 failed, 2 usage, 3 preflight failed, 4 locked, 5 aborted by the user.
  Requires PowerShell 7+ (recommended) or Windows PowerShell 5.1, Docker Desktop with Compose v2.24+.
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)][string]$Command = "",
  [Parameter(Position = 1, ValueFromRemainingArguments = $true)][string[]]$Rest
)

Set-StrictMode -Version 3
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root
$StateDir = Join-Path $Root ".run"
$StateFile = Join-Path $StateDir "state"
$LockDir = Join-Path $StateDir "lock"
$LogDir = Join-Path $Root "logs"
$LogFile = Join-Path $LogDir "run.log"
$Config = Join-Path $Root "config/exposurecatalyst.yaml"
$ConfigExample = Join-Path $Root "config/exposurecatalyst.example.yaml"
$MinCompose = [version]"2.24.0"
New-Item -ItemType Directory -Force -Path $StateDir, $LogDir | Out-Null
$script:LastBackup = ""
$script:LockHeld = $false

# ---- output ----------------------------------------------------------------------------------------------
function Ts { (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
function Log([string]$Msg) { $line = "$(Ts) $Msg"; Write-Host $line; Add-Content -Path $LogFile -Value $line }
function Ok([string]$Msg) { Log "[ok] $Msg" }
function Warn([string]$Msg) { Log "[!] $Msg" }
function Die([int]$Code, [string]$Msg) { Log "[x] $Msg"; Release-Lock; exit $Code }

# ---- lock ------------------------------------------------------------------------------------------------
function Release-Lock { if ($script:LockHeld -and (Test-Path $LockDir)) { Remove-Item -Recurse -Force $LockDir }; $script:LockHeld = $false }
function Acquire-Lock {
  try { New-Item -ItemType Directory -Path $LockDir -ErrorAction Stop | Out-Null }
  catch {
    $owner = Get-Content (Join-Path $LockDir "pid") -ErrorAction SilentlyContinue
    if ($owner -and -not (Get-Process -Id $owner -ErrorAction SilentlyContinue)) {
      Warn "removing stale lock left by pid $owner"; Remove-Item -Recurse -Force $LockDir; Acquire-Lock; return
    }
    Die 4 "another run.ps1/run.sh is running (pid $owner); remove $LockDir if that is not true"
  }
  Set-Content -Path (Join-Path $LockDir "pid") -Value $PID
  $script:LockHeld = $true
}

# ---- configuration (YAML -> compose variables; the shell environment and .env win) ------------------------
function Get-DotEnv([string]$Key) {
  $f = Join-Path $Root ".env"
  if (-not (Test-Path $f)) { return "" }
  $line = Get-Content $f | Where-Object { $_ -match "^\s*$([regex]::Escape($Key))=" } | Select-Object -Last 1
  if (-not $line) { return "" }
  $v = ($line -split "=", 2)[1] -replace "\s#.*$", ""
  return $v.Trim().Trim('"').Trim("'")
}
function Get-Yaml([string]$Key) {
  if (-not (Test-Path $Config)) { return "" }
  $lines = Get-Content $Config
  if ($Key.StartsWith("features.")) {
    $name = $Key.Substring(9); $in = $false
    foreach ($l in $lines) {
      if ($l -match "^features:") { $in = $true; continue }
      if ($in -and $l -match "^[^\s#]") { $in = $false }
      if ($in -and $l -match "^\s+$([regex]::Escape($name)):\s*(.*)$") { return ($Matches[1] -replace "\s+#.*$", "").Trim().Trim('"').Trim("'") }
    }
    return ""
  }
  foreach ($l in $lines) {
    if ($l -match "^$([regex]::Escape($Key)):\s*(.*)$") { return ($Matches[1] -replace "\s+#.*$", "").Trim().Trim('"').Trim("'") }
  }
  return ""
}
function Env-Get([string]$Name) { [Environment]::GetEnvironmentVariable($Name, "Process") }
function Env-Set([string]$Name, [string]$Value) { [Environment]::SetEnvironmentVariable($Name, $Value, "Process") }

function Adopt-DotEnv {
  foreach ($k in "EXCAT_FQDN", "EXCAT_HTTP_PORT", "EXCAT_HTTPS_PORT", "EXCAT_HTTPS_PORT_SUFFIX", "EXCAT_IMAGE_TAG",
                 "EXCAT_HEALTH_TIMEOUT", "EXCAT_WATCH_INTERVAL", "EXCAT_MIN_FREE_GB", "EXCAT_FEATURES__RUN_WATCH_MODE",
                 "COMPOSE_PROJECT_NAME", "COMPOSE_FILE") {
    if (-not (Env-Get $k)) { $v = Get-DotEnv $k; if ($v) { Env-Set $k $v } }
  }
  $tag = if (Env-Get "EXCAT_IMAGE_TAG") { Env-Get "EXCAT_IMAGE_TAG" } else { "local" }
  $script:AppImage = "exposurecatalyst:$tag"; $script:ProxyImage = "exposurecatalyst-proxy:$tag"
  $script:HealthTimeout = if (Env-Get "EXCAT_HEALTH_TIMEOUT") { Env-Get "EXCAT_HEALTH_TIMEOUT" } else { "300" }
  $script:WatchInterval = if (Env-Get "EXCAT_WATCH_INTERVAL") { [int](Env-Get "EXCAT_WATCH_INTERVAL") } else { 30 }
  $script:MinFreeGb = if (Env-Get "EXCAT_MIN_FREE_GB") { [int](Env-Get "EXCAT_MIN_FREE_GB") } else { 5 }
}
function Env-OrYaml([string]$Var, [string]$Key) {
  if (Env-Get $Var) { return }
  $v = Get-Yaml $Key
  if ($v) { Env-Set $Var $v }
}
function Ensure-Config {
  if (-not (Test-Path $Config) -and (Test-Path $ConfigExample)) {
    Copy-Item $ConfigExample $Config; Ok "created config/exposurecatalyst.yaml from the example (edit fqdn and features there)"
  }
  $envFile = Join-Path $Root ".env"
  if (-not (Test-Path $envFile) -and (Test-Path (Join-Path $Root ".env.example"))) {
    Copy-Item (Join-Path $Root ".env.example") $envFile
    Ok "created .env from .env.example (secrets stay empty: the init container generates them)"
  }
}
function Load-Config {
  Adopt-DotEnv
  Env-OrYaml "EXCAT_FQDN" "fqdn"; Env-OrYaml "EXCAT_HTTP_PORT" "http_port"; Env-OrYaml "EXCAT_HTTPS_PORT" "https_port"
  Env-OrYaml "EXCAT_TRUSTED_PROXIES" "trusted_proxies"; Env-OrYaml "TZ" "timezone"
  $proxy = Get-Yaml "outbound_proxy"
  if ($proxy) {
    if (-not (Env-Get "HTTPS_PROXY") -and -not (Get-DotEnv "HTTPS_PROXY")) { Env-Set "HTTPS_PROXY" $proxy }
    if (-not (Env-Get "HTTP_PROXY") -and -not (Get-DotEnv "HTTP_PROXY")) { Env-Set "HTTP_PROXY" $proxy }
  }
  $script:HttpPort = if (Env-Get "EXCAT_HTTP_PORT") { Env-Get "EXCAT_HTTP_PORT" } else { "80" }
  $script:HttpsPort = if (Env-Get "EXCAT_HTTPS_PORT") { Env-Get "EXCAT_HTTPS_PORT" } else { "443" }
  if (-not (Env-Get "EXCAT_HTTPS_PORT_SUFFIX") -and $script:HttpsPort -ne "443") { Env-Set "EXCAT_HTTPS_PORT_SUFFIX" ":$($script:HttpsPort)" }
  if ((Get-Yaml "database_url") -and -not (Env-Get "COMPOSE_FILE")) {
    $sep = if ($IsWindows -or $env:OS -eq "Windows_NT") { ";" } else { ":" }
    Env-Set "COMPOSE_FILE" "docker-compose.yml${sep}docker/compose.external-db.yml"
  }
  $script:Fqdn = if (Env-Get "EXCAT_FQDN") { Env-Get "EXCAT_FQDN" } else { "localhost" }
  $script:Url = if ($script:HttpsPort -eq "443") { "https://$($script:Fqdn)" } else { "https://$($script:Fqdn):$($script:HttpsPort)" }
}
function Flag-On([string]$Name) {
  $v = Env-Get ("EXCAT_FEATURES__" + $Name.ToUpper())
  if (-not $v) { $v = Get-Yaml "features.$Name" }
  return @("true", "yes", "1", "on") -contains "$v".ToLower()
}

function Dc { & docker compose @args; if ($LASTEXITCODE -ne 0) { throw "docker compose $($args -join ' ') failed ($LASTEXITCODE)" } }
function Dc-Quiet { $out = & docker compose @args 2>&1; $script:DcExit = $LASTEXITCODE; Add-Content -Path $LogFile -Value ($out | Out-String); return ($LASTEXITCODE -eq 0) }

# ---- preflight -------------------------------------------------------------------------------------------
function Test-PortOwnedByProxy([string]$Port) {
  $owned = @(& docker compose port proxy 8080 2>$null) + @(& docker compose port proxy 8443 2>$null)
  return [bool]($owned | Where-Object { $_ -match ":$Port$" })
}
function Test-PortBusy([string]$Port) {
  $c = New-Object System.Net.Sockets.TcpClient
  try { $c.Connect("127.0.0.1", [int]$Port); return $true } catch { return $false } finally { $c.Dispose() }
}
function Preflight {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Die 3 "Docker is not installed (Docker Desktop: https://docs.docker.com/get-docker/)" }
  & docker info *> $null; if ($LASTEXITCODE -ne 0) { Die 3 "the Docker daemon is not running or not reachable" }
  $cv = (& docker compose version --short 2>$null) -replace "^v", ""
  if (-not $cv) { Die 3 "Docker Compose v2 is required" }
  if ([version]($cv -replace "[^0-9.].*$", "") -lt $MinCompose) { Die 3 "Docker Compose $cv is too old; $MinCompose or newer is required" }
  foreach ($p in $script:HttpPort, $script:HttpsPort) {
    if (-not (Test-PortOwnedByProxy $p) -and (Test-PortBusy $p)) { Die 3 "port $p is in use by another program (set http_port/https_port)" }
  }
  $drive = (Get-Item $Root).PSDrive
  $freeGb = [math]::Floor($drive.Free / 1GB)
  if ($freeGb -lt $script:MinFreeGb) { Die 3 "less than $($script:MinFreeGb) GB free disk space ($freeGb GB)" }
  Ok "preflight: docker $(& docker version --format '{{.Server.Version}}'), compose $cv, ports $($script:HttpPort)/$($script:HttpsPort), disk $freeGb GB free"
}

# ---- change detection ------------------------------------------------------------------------------------
function Hash-Paths([string[]]$Paths) {
  $files = @()
  if (Get-Command git -ErrorAction SilentlyContinue) {
    $files = @(& git -C $Root ls-files -co --exclude-standard -- @Paths 2>$null | Sort-Object)
  }
  $sha = [System.Security.Cryptography.SHA256]::Create()
  $ms = New-Object System.IO.MemoryStream
  foreach ($f in $files) {
    $nameBytes = [Text.Encoding]::UTF8.GetBytes("$f`n"); $ms.Write($nameBytes, 0, $nameBytes.Length)
    $full = Join-Path $Root $f
    if (Test-Path $full -PathType Leaf) { $b = [IO.File]::ReadAllBytes($full); $ms.Write($b, 0, $b.Length) }
  }
  return ([BitConverter]::ToString($sha.ComputeHash($ms.ToArray())) -replace "-", "").ToLower()
}
function Compute-Hashes {
  $script:AppHash = Hash-Paths @("Dockerfile", ".dockerignore", "pyproject.toml", "README.md", "CHANGELOG.md", "mkdocs.yml", "alembic.ini", "src", "migrations", "docs", "brand", "frontend", "docker/caddy/Caddyfile")
  $script:ProxyHash = Hash-Paths @("Dockerfile", ".dockerignore", "frontend", "brand", "docker/caddy")
  $envDump = (Get-ChildItem Env: | Where-Object { $_.Name -match "^(EXCAT_|COMPOSE_|HTTPS?_PROXY|NO_PROXY|TZ$)" } | Sort-Object Name | ForEach-Object { "$($_.Name)=$($_.Value)" }) -join "`n"
  $extra = ""
  foreach ($f in (Join-Path $Root ".env"), $Config) { if (Test-Path $f) { $extra += (Get-FileHash $f -Algorithm SHA256).Hash } }
  $s = [System.Security.Cryptography.SHA256]::Create()
  $script:ConfHash = ([BitConverter]::ToString($s.ComputeHash([Text.Encoding]::UTF8.GetBytes((Hash-Paths @("docker-compose.yml", "docker/compose.external-db.yml", "docker/backup")) + $extra + $envDump))) -replace "-", "").ToLower()
}
function State-Get([string]$Key) {
  if (-not (Test-Path $StateFile)) { return "" }
  $l = Get-Content $StateFile | Where-Object { $_ -like "$Key=*" } | Select-Object -Last 1
  if ($l) { return $l.Substring($Key.Length + 1) } else { return "" }
}
function Save-State([string]$Version) {
  @("app_hash=$($script:AppHash)", "proxy_hash=$($script:ProxyHash)", "conf_hash=$($script:ConfHash)", "version=$Version", "last_success=$(Ts)", "url=$($script:Url)") | Set-Content -Path "$StateFile.tmp"
  Move-Item -Force "$StateFile.tmp" $StateFile
}

# ---- health / failure ------------------------------------------------------------------------------------
function Get-Services { (& docker compose ps -a --format '{{.Service}}|{{.State}}|{{.Health}}|{{.ExitCode}}' 2>$null) | Where-Object { $_ } }
function Test-AllHealthy {
  $rows = @(Get-Services); if ($rows.Count -eq 0) { return $false }
  foreach ($r in $rows) {
    $f = $r -split "\|"
    if ($f[0] -in @("init", "migrate")) { continue }
    if ($f[1] -ne "running" -or ($f[2] -and $f[2] -ne "healthy")) { return $false }
  }
  return $true
}
function Get-AppVersion {
  try {
    $handler = New-Object System.Net.Http.HttpClientHandler
    $handler.ServerCertificateCustomValidationCallback = { $true }  # self-signed on first start; reads the version only
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(5)
    $req = New-Object System.Net.Http.HttpRequestMessage("GET", "https://127.0.0.1:$($script:HttpsPort)/api/health/ready")
    $req.Headers.Host = if ($script:HttpsPort -eq "443") { $script:Fqdn } else { "$($script:Fqdn):$($script:HttpsPort)" }
    $body = $client.SendAsync($req).GetAwaiter().GetResult().Content.ReadAsStringAsync().GetAwaiter().GetResult()
    return ($body | ConvertFrom-Json).version
  } catch { return "unknown" }
}
function Show-Failure {
  Warn "deployment failed; service status:"
  & docker compose ps -a 2>&1 | Tee-Object -FilePath $LogFile -Append | Out-Host
  $failing = @()
  foreach ($r in Get-Services) {
    $f = $r -split "\|"
    if ($f[0] -in @("init", "migrate")) { if ($f[3] -ne "0") { $failing += $f[0] }; continue }
    if ($f[1] -ne "running" -or ($f[2] -and $f[2] -ne "healthy")) { $failing += $f[0] }
  }
  if ($failing.Count -eq 0) { $failing = @("api", "migrate") }
  foreach ($svc in $failing) { Warn "last logs of ${svc}:"; & docker compose logs --no-color --tail 60 $svc 2>&1 | Tee-Object -FilePath $LogFile -Append | Out-Host }
}

# ---- backup / rollback -----------------------------------------------------------------------------------
function Backup-Db {
  $running = @(& docker compose ps --services --filter status=running 2>$null)
  if ($running -notcontains "postgres") { Log "backup: bundled PostgreSQL not running (first start or external database) - skipped"; return }
  Log "backup: pg_dump -> backups volume"
  $out = & docker compose --profile backup run --rm --no-deps -T backup once 2>&1
  Add-Content -Path $LogFile -Value ($out | Out-String)
  if ($LASTEXITCODE -ne 0) { Die 1 "database backup failed - not applying changes (see logs\run.log)" }
  $m = ($out | Out-String) | Select-String -Pattern "wrote (excat-\S+\.dump)" -AllMatches
  if ($m) { $script:LastBackup = $m.Matches[-1].Groups[1].Value }
  Ok "backup: $($script:LastBackup)"
}
function Rollback-Ref([string]$Img) { $repo, $tag = $Img -split ":", 2; if ($tag -eq "local") { "${repo}:rollback" } else { "${repo}:$tag-rollback" } }
function Tag-Rollback { foreach ($img in $script:AppImage, $script:ProxyImage) { & docker image inspect $img *> $null; if ($LASTEXITCODE -eq 0) { & docker tag $img (Rollback-Ref $img) } } }
function Restore-Images {
  $restored = $false
  foreach ($img in $script:AppImage, $script:ProxyImage) {
    $rb = Rollback-Ref $img; & docker image inspect $rb *> $null
    if ($LASTEXITCODE -eq 0) { & docker tag $rb $img; $restored = $true }
  }
  if ($restored) {
    Warn "rolling back to the previous images"
    if (Dc-Quiet up -d --remove-orphans --wait --wait-timeout $script:HealthTimeout) { Ok "previous version is running again" } else { Warn "the previous version did not become healthy either - check: .\run.ps1 logs" }
  } else { Warn "no rollback images exist (first deployment) - nothing to roll back to" }
  if ($script:LastBackup) {
    Warn "if the failed version changed the database schema, restore the pre-migration backup:"
    Warn "    .\run.ps1 restore $($script:LastBackup)      (asks for confirmation; never automatic)"
  }
}

# ---- main flow -------------------------------------------------------------------------------------------
function Deploy {
  Ensure-Config; Load-Config; Preflight; Compute-Hashes
  $prevApp = State-Get "app_hash"; $prevProxy = State-Get "proxy_hash"; $prevConf = State-Get "conf_hash"
  if ($script:AppHash -eq $prevApp -and $script:ProxyHash -eq $prevProxy -and $script:ConfHash -eq $prevConf -and (Test-AllHealthy)) {
    if ($env:EXCAT_WATCHING) { Add-Content -Path $LogFile -Value "$(Ts) unchanged" } else { Ok "nothing changed since $(State-Get 'last_success') and all services are healthy - $($script:Url) ($(State-Get 'version'))" }
    return
  }
  & docker image inspect $script:AppImage *> $null; $buildApp = ($script:AppHash -ne $prevApp) -or ($LASTEXITCODE -ne 0)
  & docker image inspect $script:ProxyImage *> $null; $buildProxy = ($script:ProxyHash -ne $prevProxy) -or ($LASTEXITCODE -ne 0)
  Log ("changes: app image " + $(if ($buildApp) { "rebuild" } else { "unchanged" }) + ", proxy image " + $(if ($buildProxy) { "rebuild" } else { "unchanged" }) + ", configuration " + $(if ($script:ConfHash -ne $prevConf) { "changed" } else { "unchanged" }))
  Tag-Rollback
  if ($buildApp) { Log "building $($script:AppImage)"; if (-not (Dc-Quiet build api)) { Die 1 "image build failed (nothing was changed)" } }
  if ($buildProxy) { Log "building $($script:ProxyImage)"; if (-not (Dc-Quiet build proxy)) { Die 1 "image build failed (nothing was changed)" } }
  if ($buildApp) { Backup-Db }
  Log "starting services (migrations run first; waiting up to $($script:HealthTimeout)s for health)"
  if (Dc-Quiet up -d --remove-orphans --wait --wait-timeout $script:HealthTimeout) {
    $v = Get-AppVersion; Save-State $v; Ok "ExposureCatalyst $v is up: $($script:Url)"
    if ($script:Fqdn -eq "localhost") { Log "  (self-signed certificate until you install one - Settings > Certificates & Domain)" }
    if ((& docker compose logs api 2>$null | Out-String) -match "one-time setup token") { Log "  first run: open $($script:Url)/setup - token: .\run.ps1 logs api" }
    return
  }
  Show-Failure; Restore-Images; Release-Lock; exit 1
}

function Require-Docker {
  if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { Die 3 "Docker is not installed (Docker Desktop: https://docs.docker.com/get-docker/)" }
}
function Cmd-Status {
  Require-Docker; Load-Config; & docker compose ps -a | Out-Host
  if (Test-AllHealthy) { Ok "all services healthy - $($script:Url) ($(Get-AppVersion))" } else { Warn "not all services are healthy" }
  if (Test-Path $StateFile) { Log "last successful run: $(State-Get 'last_success') (version $(State-Get 'version'))" }
}
function Cmd-Restore([string]$File) {
  if (-not $File) { Die 2 "usage: .\run.ps1 restore <excat-YYYYMMDDTHHMMSSZ.dump>" }
  if ($File -match "[\\/]|\.\.") { Die 2 "give the backup file name only (it is read from the backups volume)" }
  Load-Config
  & docker compose --profile backup run --rm --no-deps -T --entrypoint test backup -f "/backups/$File" *> $null
  if ($LASTEXITCODE -ne 0) { Die 1 "backup $File not found in the backups volume" }
  Warn "This REPLACES the current database with $File. Current data not in that backup is lost."
  Warn "A safety backup of the current database is taken first."
  $answer = if ([Environment]::UserInteractive -and -not $env:EXCAT_CONFIRM_RESTORE) { Read-Host "Type RESTORE to continue" } else { $env:EXCAT_CONFIRM_RESTORE }
  if ($answer -cne "RESTORE") { Die 5 "restore aborted" }
  Acquire-Lock; Backup-Db
  Log "stopping api / scheduler / proxy"; Dc-Quiet stop proxy api scheduler | Out-Null
  Log "restoring $File"
  $cmd = 'PGPASSWORD="$(cat /run/db-secret/db_password)" pg_restore -h postgres -U excat -d excat --clean --if-exists --no-owner "/backups/' + $File + '"'
  if (Dc-Quiet --profile backup run --rm --no-deps -T --entrypoint sh backup -c $cmd) { Ok "database restored" } else { Warn "pg_restore reported errors (see logs\run.log); starting the services anyway" }
  if (Dc-Quiet up -d --wait --wait-timeout $script:HealthTimeout) { Ok "services up: $($script:Url)" } else { Die 1 "services did not become healthy" }
}
function Cmd-Update {
  if ((& git -C $Root status --porcelain --untracked-files=no) ) { Die 1 "local changes in tracked files - commit or stash them before .\run.ps1 update" }
  Log "git pull --ff-only (branch $(& git -C $Root rev-parse --abbrev-ref HEAD))"
  & git -C $Root pull --ff-only *>> $LogFile; if ($LASTEXITCODE -ne 0) { Die 1 "git pull failed (see logs\run.log)" }
  Ok "now at $(& git -C $Root log -1 --format='%h %s')"; Deploy
}
function Cmd-Watch {
  Load-Config
  if (-not (Flag-On "run_watch_mode")) { Die 1 "watch mode is disabled - set features.run_watch_mode: true in config\exposurecatalyst.yaml (dev/test only)" }
  Log "watch mode: checking for changes every $($script:WatchInterval)s (Ctrl-C to stop)"
  $env:EXCAT_WATCHING = "1"
  while ($true) {
    try { Acquire-Lock; Deploy } catch { Warn "apply failed: $($_.Exception.Message); will retry on the next change" } finally { Release-Lock }
    Start-Sleep -Seconds $script:WatchInterval
  }
}
function Cmd-Doctor {
  Require-Docker; Ensure-Config; Load-Config; $rc = 0
  Log "== versions"; Log "docker $(& docker version --format '{{.Server.Version}}'), compose $(& docker compose version --short), PowerShell $($PSVersionTable.PSVersion)"
  Log "== services"; if (Test-AllHealthy) { Ok "all services healthy" } else { Warn "not all services healthy"; $rc = 1 }
  Get-Services | ForEach-Object { Log "  $_" }
  Log "== domain"; Log "fqdn: $($script:Fqdn)  url: $($script:Url)"
  if ($script:Fqdn -ne "localhost") {
    try { $ip = [System.Net.Dns]::GetHostAddresses($script:Fqdn)[0]; Ok "$($script:Fqdn) resolves to $ip" } catch { Warn "$($script:Fqdn) does not resolve (create the DNS record - see Map your domain)"; $rc = 1 }
  }
  Log "== disk"; $free = [math]::Floor((Get-Item $Root).PSDrive.Free / 1GB); if ($free -lt $script:MinFreeGb) { Warn "only $free GB free"; $rc = 1 } else { Ok "$free GB free" }
  Log "== last run"; if (Test-Path $StateFile) { Log "success at $(State-Get 'last_success'), version $(State-Get 'version')" } else { Log "no successful run recorded" }
  exit $rc
}
function Usage {
  @"
Usage: .\run.ps1 [command]

  (no command)    bring the app up, or apply changes since the last successful run and restart
  start           start the services (no rebuild)
  stop            stop the services (data is kept)
  restart         restart the services and wait for health
  update          git pull (current branch, fast-forward only) then apply as above
  status          service status, health, version
  logs [service]  follow logs (all services, or e.g. api, proxy, scheduler)
  backup          pg_dump of the bundled PostgreSQL into the backups volume
  restore <file>  restore a backup (asks for confirmation; takes a safety backup first)
  watch           poll for changes and apply them - needs features.run_watch_mode: true (dev/test only)
  doctor          diagnostics: health, DNS, disk, versions
  help            this help

Configuration: config\exposurecatalyst.yaml (created from the example on first run) and .env.
Environment: EXCAT_HEALTH_TIMEOUT (300), EXCAT_WATCH_INTERVAL (30), EXCAT_MIN_FREE_GB (5).   Log: logs\run.log
"@
}

try {
  switch ($Command) {
    "" { Acquire-Lock; Deploy }
    "start" { Acquire-Lock; Ensure-Config; Load-Config; Preflight; if (Dc-Quiet up -d --no-build --wait --wait-timeout $script:HealthTimeout) { Ok "started: $($script:Url)" } else { Show-Failure; exit 1 } }
    "stop" { Acquire-Lock; Adopt-DotEnv; Dc-Quiet stop | Out-Null; Ok "stopped (data kept)" }
    "restart" { Acquire-Lock; Load-Config; Dc-Quiet restart | Out-Null; if (Dc-Quiet up -d --no-build --wait --wait-timeout $script:HealthTimeout) { Ok "restarted: $($script:Url)" } else { Show-Failure; exit 1 } }
    "update" { Acquire-Lock; Cmd-Update }
    "status" { Cmd-Status }
    "logs" { Require-Docker; Adopt-DotEnv; & docker compose logs -f --tail 200 @Rest }
    "backup" { Acquire-Lock; Load-Config; Backup-Db }
    "restore" { Cmd-Restore ($Rest | Select-Object -First 1) }
    "watch" { Cmd-Watch }
    "doctor" { Cmd-Doctor }
    { $_ -in @("help", "-h", "--help") } { Usage }
    default { Usage; exit 2 }
  }
} finally {
  Release-Lock
}
