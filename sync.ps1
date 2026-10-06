# Auto-Upstream + Pull (PowerShell)
$currentBranch = git branch --show-current

$upstream = git rev-parse --abbrev-ref "$($currentBranch)@{upstream}" 2>$null

if (-not $upstream) {
    Write-Host "No upstream set → setting origin/$currentBranch ..."
    git branch --set-upstream-to=origin/$currentBranch $currentBranch
} else {
    Write-Host "Upstream is already set: $upstream"
}

git pull --ff-only
