#!/bin/bash
#
# Script to build a Debian (.deb) package for the gnoppix-gpg-generator application.
#
# USAGE:
# 1. Ensure you have the 'gnoppix_gpggen' executable (e.g., Python script)
#    and 'gnoppix_gpggen.desktop' file in this directory.
# 2. Run the script: bash make_deb.sh
# 3. The final package will be created in the current directory.

# --- Configuration Variables ---
PACKAGE_NAME="gnoppix-gpg-generator"
VERSION="1.6" # Updated to match your latest build output
ARCHITECTURE="all" # 'all' for scripts like Python, 'amd64' for compiled binaries
MAINTAINER="Gnoppix Linux <gnoppix@gnoppix.com>"
DESCRIPTION_SHORT="Gnoppix GPG Key Generator Tool."
DESCRIPTION_LONG="A GUI application written in Python to simplify the generation of PGP (GPG) keys for users."
BUILD_DIR="${PACKAGE_NAME}_${VERSION}"
OUTPUT_FILE="${PACKAGE_NAME}_${VERSION}_${ARCHITECTURE}.deb"

# --- Source Files (Expected to be in the same directory as this script) ---
SOURCE_BIN="./gnoppix_gpggen"
# Corrected desktop file name: underscore is used
SOURCE_DESKTOP="./gnoppix_gpggen.desktop"

# Check for prerequisites
if [ ! -f "$SOURCE_BIN" ] || [ ! -f "$SOURCE_DESKTOP" ]; then
    echo "ERROR: Missing source files. Ensure both '$SOURCE_BIN' and '$SOURCE_DESKTOP' exist."
    exit 1
fi

# 1. Clean up previous build directories and packages
echo "--- Cleaning up previous build artifacts ---"
rm -rf "$BUILD_DIR"
rm -f "$OUTPUT_FILE"

# 2. Create the package structure and DEBIAN control directory 
echo "--- Creating package directory structure: $BUILD_DIR ---"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/usr/bin"
mkdir -p "$BUILD_DIR/usr/share/applications"

# 3. Create the DEBIAN/control file
echo "--- Creating DEBIAN/control file ---"
cat > "$BUILD_DIR/DEBIAN/control" << EOF
Package: $PACKAGE_NAME
Version: $VERSION
Section: utils
Priority: optional
Architecture: $ARCHITECTURE
Installed-Size: \$(du -ks $BUILD_DIR | cut -f 1)
Maintainer: $MAINTAINER
Depends: python3, python3-tkinter, python3-pyqt6, gnupg
Description: $DESCRIPTION_SHORT
 $DESCRIPTION_LONG
EOF

# 4. Copy the application files to the correct target paths
echo "--- Copying application files into package structure ---"
# Executable to /usr/bin
cp "$SOURCE_BIN" "$BUILD_DIR/usr/bin/$PACKAGE_NAME"
# Desktop file to /usr/share/applications
cp "$SOURCE_DESKTOP" "$BUILD_DIR/usr/share/applications/"

# Ensure the executable has correct permissions (755)
chmod 755 "$BUILD_DIR/usr/bin/$PACKAGE_NAME"

# 5. Create a post-installation script to update the desktop database
# This ensures the new desktop entry appears in the application menu immediately.
echo "--- Creating DEBIAN/postinst script ---"
cat > "$BUILD_DIR/DEBIAN/postinst" << EOF_POSTINST
#!/bin/sh
set -e

# Update the desktop file database to make the new launcher visible
if which update-desktop-database >/dev/null 2>&1; then
    update-desktop-database
fi

exit 0
EOF_POSTINST

# Ensure the maintainer scripts have correct permissions (755)
chmod 755 "$BUILD_DIR/DEBIAN/postinst"

# 6. Build the .deb package
echo "--- Building the .deb package: $OUTPUT_FILE ---"
# FIX: Removed '=root:root' as this version of dpkg-deb expects the flag alone,
# which defaults to setting ownership to root:root (0:0).
dpkg-deb --build --root-owner-group "$BUILD_DIR" "$OUTPUT_FILE"

if [ $? -eq 0 ]; then
    echo ""
    echo "SUCCESS: Debian package created at: $OUTPUT_FILE"
    echo "You can install it using: sudo dpkg -i $OUTPUT_FILE"
    echo "Remember to run 'sudo apt install -f' if dependency issues arise."
else
    echo ""
    echo "ERROR: Failed to build the Debian package."
fi

# 7. Clean up the build directory (optional, commented out for inspection)
# rm -rf "$BUILD_DIR"
