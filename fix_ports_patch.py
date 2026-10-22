#!/usr/bin/env python3
"""Fix buildPortsPanel to show 'No open ports found' when ports are closed."""

import io

FILE_PATH = 'c:/Users/comp/threatintel-platform/src/darkweb_scanner/dashboard/templates/index.html'

with io.open(FILE_PATH, 'r', encoding='utf-8') as f:
    content = f.read()

# Patch 1: buildPortsPanel - show "No open ports found" when portsData is empty
old = '''//  Ports View 
function buildPortsPanel(portScan, mainIPs, domain) {
     // Backend returns: {target, ip, ports: {"21": "open", "80": "open", ...}}
     const portsData = portScan && portScan.ports ? portScan.ports : {};
     const hasData = Object.keys(portsData).length > 0;
     if (!hasData) {
       const scanIP = portScan && portScan.ip ? portScan.ip : (mainIPs[0] || domain);
       return `<div style="text-align:center;padding:40px 20px">
         <div style="font-size:2rem;margin-bottom:12px"></div>
         <div style="font-weight:600;margin-bottom:6px">Port scan not yet run</div>
         <div style="color:var(--muted);font-size:.83rem;margin-bottom:16px">Click the button below to actively scan all resolved IPs for open ports.</div>
         <button class="btn btn-primary" onclick="triggerPortScan(${_dnsCurrent?.id}, 'ports')"> Run Port Scan</button>
         <div style="margin-top:10px;font-size:.75rem;color:var(--muted)">Scans ${mainIPs.length} IPs across 30 common ports</div>
       </div>`;
     }'''

new = '''//  Ports View 
function buildPortsPanel(portScan, mainIPs, domain) {
     // Backend returns: {target, ip, ports: {"21": "open", "80": "open", ...}}
     const portsData = portScan && portScan.ports ? portScan.ports : {};
     const scanIP = portScan && portScan.ip ? portScan.ip : (mainIPs[0] || domain);

     // If portScan itself is empty, scan hasn't run yet
     if (!portScan || Object.keys(portScan).length === 0) {
       return `<div style="text-align:center;padding:40px 20px">
         <div style="font-size:2rem;margin-bottom:12px"></div>
         <div style="font-weight:600;margin-bottom:6px">Port scan not yet run</div>
         <div style="color:var(--muted);font-size:.83rem;margin-bottom:16px">Click the button below to actively scan all resolved IPs for open ports.</div>
         <button class="btn btn-primary" onclick="triggerPortScan(${_dnsCurrent?.id}, 'ports')"> Run Port Scan</button>
         <div style="margin-top:10px;font-size:.75rem;color:var(--muted)">Scans ${mainIPs.length} IPs across 30 common ports</div>
       </div>`;
     }

     // Ports data exists but all ports closed/filtered -> show "No open ports found"
     if (Object.keys(portsData).length === 0) {
       return `<div style="text-align:center;padding:40px 20px">
         <div style="font-size:2rem;margin-bottom:12px"></div>
         <div style="font-weight:600;margin-bottom:6px;color:var(--green)">No open ports found</div>
         <div style="color:var(--muted);font-size:.83rem;margin-bottom:16px">All ${mainIPs.length} scanned IPs had all 30 common ports closed or filtered.</div>
         <div style="margin-top:10px;font-size:.75rem;color:var(--muted)">Scans ${mainIPs.length} IPs across 30 common ports</div>
       </div>`;
     }'''

if old in content:
    content = content.replace(old, new)
    with io.open(FILE_PATH, 'w', encoding='utf-8') as f:
        f.write(content)
    print("Patched buildPortsPanel")
else:
    print("ERROR: buildPortsPanel pattern not found")