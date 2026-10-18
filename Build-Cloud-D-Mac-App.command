#!/bin/zsh
set -e
cd -- "$(dirname -- "$0")"
rm -rf "Cloud-D.app"
chmod +x Run-Cloud-D-Background-macOS.sh
mkdir -p "Cloud-D.app/Contents/MacOS"
resource_root="Cloud-D.app/Contents/Resources/CloudDProject"
mkdir -p "$resource_root"
cp index.html cloud-d.js requirements.txt Run-Cloud-D-Background-macOS.sh "$resource_root/"
cp -R cloud_d "$resource_root/cloud_d"
find "$resource_root/cloud_d" -type d -name "__pycache__" -prune -exec rm -rf {} +
rm -rf "$resource_root/cloud_d/results"
clang -fobjc-arc -fblocks -framework Cocoa -framework AppKit -framework Foundation Cloud-D-Launcher.m -o "Cloud-D.app/Contents/MacOS/Cloud-D"
cat >"Cloud-D.app/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleExecutable</key>
	<string>Cloud-D</string>
	<key>CFBundleIdentifier</key>
	<string>edu.psgtech.cloudd.launcher</string>
	<key>CFBundleName</key>
	<string>Cloud-D</string>
	<key>CFBundleDisplayName</key>
	<string>Cloud-D</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>LSMinimumSystemVersion</key>
	<string>12.0</string>
	<key>NSHighResolutionCapable</key>
	<true/>
</dict>
</plist>
PLIST
print "Created Cloud-D.app. Double-click it once to install the automatic background service."
