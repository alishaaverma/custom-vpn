param(
  [int]$Port = 9443
)

Write-Host "Checking Python runtime..."
python main.py check

Write-Host "Creating inbound firewall rule for the overlay server port $Port..."
New-NetFirewallRule `
  -DisplayName "Custom Python Overlay VPN TCP $Port" `
  -Direction Inbound `
  -Protocol TCP `
  -LocalPort $Port `
  -Action Allow `
  -Profile Any `
  -ErrorAction SilentlyContinue | Out-Null

Write-Host "Done. If clients are outside your LAN, forward TCP $Port on your router to this machine."
