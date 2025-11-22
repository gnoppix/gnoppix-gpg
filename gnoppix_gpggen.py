#------------------------------------------------------------------
# Description: Gnoppix GPG KeyGen Dialogue for Debian / Trixie 
# Authors: Andreas Mueller
# Website: https://www.gnoppix.org
# Version 1.6 - 11/22/25 
#------------------------------------------------------------------



import sys
import secrets
import shutil
import subprocess
import re
import datetime
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGroupBox, QRadioButton, QLineEdit, QComboBox, QPushButton,
    QTextEdit, QLabel, QMessageBox, QGridLayout, QFrame, QScrollArea,
    QProgressBar, QDialog, QInputDialog, QMenu
)
from PyQt6.QtGui import QFont, QIcon, QPalette, QColor, QClipboard, QAction
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# ---------------------------------------------------------
# Configuration & Helpers
# ---------------------------------------------------------
def get_gpg_binary():
    """Prioritize gpg2 if available, otherwise fall back to gpg."""
    if shutil.which("gpg2"):
        return "gpg2"
    return "gpg"

GPG_BIN = get_gpg_binary()
KEYSERVERS = [
    "hkps://keys.openpgp.org",
    "hkps://keyserver.ubuntu.com"
]

# ---------------------------------------------------------
# Worker Thread for GPG Execution
# ---------------------------------------------------------
class GpgWorker(QThread):
    finished = pyqtSignal(bool, str) # success, message

    def __init__(self, batch_input):
        super().__init__()
        self.batch_input = batch_input

    def run(self):
        try:
            # Run GPG in batch mode
            process = subprocess.Popen(
                [GPG_BIN, '--batch', '--generate-key'],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(input=self.batch_input)
            
            if process.returncode == 0:
                self.finished.emit(True, f"SUCCESS:\n{stderr}") 
            else:
                self.finished.emit(False, f"ERROR:\n{stderr}")
        except Exception as e:
            self.finished.emit(False, f"SYSTEM ERROR: {str(e)}")

class GpgPublishWorker(QThread):
    finished = pyqtSignal(bool, str) # success, message

    def __init__(self, fingerprint, keyserver):
        super().__init__()
        self.fingerprint = fingerprint
        self.keyserver = keyserver

    def run(self):
        try:
            cmd = [
                GPG_BIN, '--keyserver', self.keyserver, 
                '--send-keys', self.fingerprint
            ]
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30 # Set a timeout for the keyserver operation
            )
            
            if process.returncode == 0:
                self.finished.emit(True, f"Successfully uploaded key to {self.keyserver}") 
            else:
                # Check for common failure messages in stderr/stdout
                error_msg = process.stderr if process.stderr else process.stdout
                self.finished.emit(False, f"Failed to upload key to {self.keyserver}. Error: {error_msg}")
        except subprocess.TimeoutExpired:
            self.finished.emit(False, f"Keyserver {self.keyserver} timed out.")
        except Exception as e:
            self.finished.emit(False, f"SYSTEM ERROR during publish: {str(e)}")

# ---------------------------------------------------------
# Custom Dialog for Key Details (Creation & Info)
# ---------------------------------------------------------
class KeyDetailsDialog(QDialog):
    def __init__(self, details, title="Key Details", parent=None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.resize(600, 500)
        self.setStyleSheet("background-color: #111827; color: #F3F4F6;")
        
        layout = QVBoxLayout(self)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #34D399; margin-bottom: 10px;")
        layout.addWidget(lbl_title)
        
        lbl_info = QLabel("Please save the following details immediately.")
        lbl_info.setWordWrap(True)
        lbl_info.setStyleSheet("color: #9CA3AF; margin-bottom: 10px;")
        layout.addWidget(lbl_info)
        
        self.text_area = QTextEdit()
        self.text_area.setReadOnly(True)
        self.text_area.setText(details)
        self.text_area.setStyleSheet("""
            QTextEdit { 
                background-color: #1F2937; 
                border: 1px solid #374151; 
                border-radius: 8px; 
                padding: 15px; 
                font-family: 'Courier New'; 
                font-size: 14px; 
                color: #E5E7EB;
            }
        """)
        layout.addWidget(self.text_area)
        
        btn_layout = QHBoxLayout()
        
        self.btn_copy = QPushButton("Copy All Information")
        self.btn_copy.setStyleSheet("""
            QPushButton { background-color: #059669; color: white; padding: 10px; border-radius: 6px; font-weight: bold; }
            QPushButton:hover { background-color: #10B981; }
        """)
        self.btn_copy.clicked.connect(self.copy_to_clipboard)
        
        self.btn_close = QPushButton("Close")
        self.btn_close.setStyleSheet("""
            QPushButton { background-color: #374151; color: white; padding: 10px; border-radius: 6px; }
            QPushButton:hover { background-color: #4B5563; }
        """)
        self.btn_close.clicked.connect(self.accept)
        
        btn_layout.addWidget(self.btn_copy)
        btn_layout.addWidget(self.btn_close)
        layout.addLayout(btn_layout)
        
    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.text_area.toPlainText())
        QMessageBox.information(self, "Copied", "Key details copied to clipboard!")

# ---------------------------------------------------------
# Main Application
# ---------------------------------------------------------
STYLESHEET = """
QMainWindow { background-color: #111827; color: #F3F4F6; }
QScrollArea { border: none; background-color: #111827; }
QWidget#central_widget { background-color: #111827; }
QLabel#title_label { color: #F9FAFB; font-size: 24px; font-weight: bold; margin-bottom: 5px; }
QLabel#desc_label { color: #9CA3AF; font-size: 14px; margin-bottom: 15px; }
QGroupBox { background-color: #1F2937; border: 1px solid #374151; border-radius: 12px; margin-top: 1.5em; padding-top: 15px; font-weight: bold; color: #E5E7EB; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 8px; left: 15px; color: #34D399; background-color: #1F2937; font-size: 13px; }
QLabel { color: #D1D5DB; font-size: 13px; }
QLineEdit, QComboBox { background-color: #374151; border: 1px solid #4B5563; border-radius: 8px; padding: 10px; color: white; font-size: 13px; }
QLineEdit:focus, QComboBox:focus { border: 2px solid #10B981; background-color: #1F2937; }
QRadioButton { color: #E5E7EB; spacing: 8px; font-size: 14px; }
QPushButton { background-color: #059669; color: white; border-radius: 8px; padding: 14px; font-weight: bold; font-size: 15px; border: none; }
QPushButton:hover { background-color: #10B981; }
QPushButton:pressed { background-color: #047857; }
QPushButton:disabled { background-color: #374151; color: #9CA3AF; }
QTextEdit { background-color: #0F172A; border: 1px solid #334155; border-radius: 8px; color: #4ADE80; font-family: 'Courier New', monospace; font-size: 12px; padding: 10px; }
QMenuBar { background-color: #1F2937; color: #F3F4F6; font-size: 14px; }
QMenuBar::item { padding: 8px 12px; background-color: transparent; }
QMenuBar::item:selected { background-color: #374151; }
QMenu { background-color: #1F2937; color: #F3F4F6; border: 1px solid #374151; }
QMenu::item { padding: 8px 24px; }
QMenu::item:selected { background-color: #10B981; color: white; }
"""

class ModernGpgWizard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Gnoppix GPG Key generator for Gnoppix 26")
        self.resize(900, 850)
        self.setStyleSheet(STYLESHEET)
        
        self.last_generated_email = None # Store the email of the last generated key

        self.init_menu()

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        self.setCentralWidget(scroll_area)
        container = QWidget()
        container.setObjectName("central_widget")
        scroll_area.setWidget(container)

        self.main_layout = QVBoxLayout(container)
        self.main_layout.setContentsMargins(30, 30, 30, 30)
        self.main_layout.setSpacing(20)

        self.setup_ui()

    def init_menu(self):
        menu_bar = self.menuBar()
        
        # NOTE: Full right-alignment of specific items is not standard 
        # behavior for QMenuBar and is often platform-dependent or requires 
        # complex workarounds (like using a QWidget instead of QMenuBar). 
        # We will use the standard order: Publish, Option, Help, Quit.

        # Publish Menu
        publish_menu = menu_bar.addMenu("Publish")
        action_publish_last = QAction("Publish Last Generated Key", self)
        action_publish_last.triggered.connect(self.menu_publish_key)
        publish_menu.addAction(action_publish_last)
        
        action_publish_email = QAction("Publish Key by Email...", self)
        action_publish_email.triggered.connect(lambda: self.menu_publish_key(request_email=True))
        publish_menu.addAction(action_publish_email)

        # Option Menu
        option_menu = menu_bar.addMenu("Option")
        
        action_edit = QAction("Edit Key (Change Passphrase)", self)
        action_edit.triggered.connect(self.menu_edit_key)
        option_menu.addAction(action_edit)

        action_info = QAction("Display Key Info", self)
        action_info.triggered.connect(self.menu_display_info)
        option_menu.addAction(action_info)

        # Help Menu
        help_menu = menu_bar.addMenu("Help")
        
        action_help = QAction("Help", self)
        action_help.triggered.connect(self.menu_help)
        help_menu.addAction(action_help)

        action_about = QAction("About", self)
        action_about.triggered.connect(self.menu_about)
        help_menu.addAction(action_about)

        # Quit Action
        action_quit = QAction("Quit", self)
        action_quit.triggered.connect(self.close)
        menu_bar.addAction(action_quit)

    def setup_ui(self):
        title = QLabel("Gnoppix GPG Key Generator")
        title.setObjectName("title_label")
        desc = QLabel(f"Using binary: {GPG_BIN}. Fully automated GPG key creation. Checks for existing keys, deletes them if requested, and generates a secure identity.")
        desc.setObjectName("desc_label")
        desc.setWordWrap(True)
        self.main_layout.addWidget(title)
        self.main_layout.addWidget(desc)

        self.create_step1()
        self.create_step2()
        self.create_action_area()
        self.create_output_area()

    def create_step1(self):
        group = QGroupBox("Step 1: Choose Encryption Strength")
        layout = QVBoxLayout()
        
        self.radio_quick = QRadioButton("Quick Encryption (ECC / Ed25519)")
        lbl_quick = QLabel("Fast & Modern (256-bit). Ideal for standard hardware.")
        lbl_quick.setStyleSheet("color: #9CA3AF; font-size: 12px; margin-left: 28px;")
        
        self.radio_military = QRadioButton("Military High Grade Encryption (RSA 4096)")
        self.radio_military.setChecked(True)
        lbl_mil = QLabel("Maximum Classical Strength. RSA 4096-bit.")
        lbl_mil.setStyleSheet("color: #9CA3AF; font-size: 12px; margin-left: 28px;")

        layout.addWidget(self.radio_quick)
        layout.addWidget(lbl_quick)
        layout.addSpacing(10)
        layout.addWidget(self.radio_military)
        layout.addWidget(lbl_mil)
        group.setLayout(layout)
        self.main_layout.addWidget(group)

    def create_step2(self):
        group = QGroupBox("Step 2: User Details")
        layout = QGridLayout()
        layout.setVerticalSpacing(15)

        layout.addWidget(QLabel("Real Name:"), 0, 0)
        self.input_name = QLineEdit()
        self.input_name.setPlaceholderText("e.g., Jane Doe")
        layout.addWidget(self.input_name, 0, 1)

        layout.addWidget(QLabel("Email Address:"), 1, 0)
        self.input_email = QLineEdit()
        self.input_email.setPlaceholderText("e.g., jane@example.com")
        layout.addWidget(self.input_email, 1, 1)

        layout.addWidget(QLabel("Key Validity:"), 2, 0)
        self.combo_validity = QComboBox()
        for label, val in [("Select...", ""), ("1 Month", "1m"), ("1 Year", "1y"), ("5 Years", "5y"), ("10 Years", "10y"), ("Never", "0")]:
            self.combo_validity.addItem(label, val)
        layout.addWidget(self.combo_validity, 2, 1)

        layout.addWidget(QLabel("Comment:"), 3, 0)
        self.input_comment = QLineEdit()
        layout.addWidget(self.input_comment, 3, 1)

        group.setLayout(layout)
        self.main_layout.addWidget(group)

    def create_action_area(self):
        self.btn_create = QPushButton("Create GPG Key Now")
        self.btn_create.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_create.clicked.connect(self.start_creation_process)
        self.main_layout.addWidget(self.btn_create)

        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        self.progress.setStyleSheet("QProgressBar { border: 0px; background: #374151; height: 4px; } QProgressBar::chunk { background: #10B981; }")
        self.main_layout.addWidget(self.progress)

    def create_output_area(self):
        group = QGroupBox("Step 3: Process Log")
        layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setMinimumHeight(150)
        layout.addWidget(self.output_text)
        group.setLayout(layout)
        self.main_layout.addWidget(group)

    # -----------------------------------------------------
    # Logic & Automation
    # -----------------------------------------------------
    def check_dependencies(self):
        if not shutil.which(GPG_BIN):
            QMessageBox.critical(self, "Error", f"{GPG_BIN} is not installed. Please run: sudo apt install gnupg2")
            return False
        return True

    def handle_existing_keys(self):
        """Checks for keys and deletes them if confirmed."""
        try:
            sec_keys = subprocess.run([GPG_BIN, '--list-secret-keys', '--with-colons'], capture_output=True, text=True)
            if "sec:" not in sec_keys.stdout:
                return True 

            reply = QMessageBox.question(
                self, "Existing Keys Found",
                "WARNING: Existing GPG secret keys were found.\n\n"
                "To generate a clean identity as requested, we must DELETE ALL existing keys.\n"
                "This action is irreversible.\n\n"
                "Do you want to DELETE ALL keys and proceed?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No
            )

            if reply == QMessageBox.StandardButton.No:
                return False

            self.log("User requested cleanup. Deleting all existing keys...")
            
            fingerprints = []
            for line in sec_keys.stdout.splitlines():
                if line.startswith("fpr:"):
                    fingerprints.append(line.split(":")[9])

            for fpr in fingerprints:
                self.log(f"Deleting secret key: {fpr}")
                subprocess.run([GPG_BIN, '--batch', '--yes', '--delete-secret-keys', fpr], capture_output=True)
            
            for fpr in fingerprints:
                self.log(f"Deleting public key: {fpr}")
                subprocess.run([GPG_BIN, '--batch', '--yes', '--delete-keys', fpr], capture_output=True)

            self.log("All existing keys deleted.")
            return True

        except Exception as e:
            self.log(f"Error handling keys: {e}")
            return False

    def get_key_details_block(self, email):
        try:
            result = subprocess.run([GPG_BIN, '--list-keys', '--with-colons', email], capture_output=True, text=True)
            lines = result.stdout.splitlines()
            
            key_id = "Unknown"
            fingerprint = "Unknown"
            uid = "Unknown"
            validity_str = "Unknown"
            
            for line in lines:
                parts = line.split(':')
                if parts[0] == 'pub':
                    key_id = parts[4][-16:]
                    # Field 7 is expiration time (seconds since epoch)
                    if len(parts) > 6 and parts[6]:
                        try:
                            ts = int(parts[6])
                            dt = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d')
                            validity_str = f"Expires: {dt}"
                        except:
                             validity_str = "Unknown Date"
                    else:
                        validity_str = "Never Expires"
                        
                if parts[0] == 'fpr':
                    fingerprint = parts[9]
                if parts[0] == 'uid':
                    uid = parts[9]
            
            if key_id == "Unknown":
                return "Key not found.", None
                
            formatted_fpr = " ".join(fingerprint[i:i+4] for i in range(0, len(fingerprint), 4))
            
            details = (
                "=================================================\n"
                "           GPG KEY INFORMATION                   \n"
                "=================================================\n"
                f"User ID:        {uid}\n"
                f"Validity:       {validity_str}\n"
                "-------------------------------------------------\n"
                f"Key ID:         {key_id}\n"
                f"Fingerprint:    {formatted_fpr}\n"
                "=================================================\n"
            )
            return details, fingerprint
        except Exception as e:
            return f"Error retrieving key details: {e}", None

    # -----------------------------------------------------
    # Menu Actions
    # -----------------------------------------------------
    def menu_display_info(self):
        email, ok = QInputDialog.getText(self, "Key Info", "Enter Email Address of the key:")
        if ok and email:
            details, _ = self.get_key_details_block(email)
            dialog = KeyDetailsDialog(details, title="Key Information", parent=self)
            dialog.exec()

    def menu_edit_key(self):
        email, ok = QInputDialog.getText(self, "Edit Key", "Enter Email Address of the key to edit:")
        if not ok or not email: return

        details, fingerprint = self.get_key_details_block(email)
        if not fingerprint:
            QMessageBox.warning(self, "Error", "Key not found.")
            return

        old_pass, ok = QInputDialog.getText(self, "Authentication", "Enter CURRENT Passphrase:", QLineEdit.EchoMode.Password)
        if not ok or not old_pass: return

        # Generate new strong passphrase (32 hex chars = 16 bytes)
        new_passphrase = secrets.token_hex(16)

        self.log(f"Attempting to update passphrase using {GPG_BIN}...")

        try:
            # ATTEMPT 1: Try the modern 'quick-set-passphrase' method first
            cmd = [
                GPG_BIN, '--batch', '--yes', '--pinentry-mode', 'loopback',
                '--passphrase', old_pass, 
                '--quick-set-passphrase', fingerprint, new_passphrase
            ]
            
            proc = subprocess.run(cmd, capture_output=True, text=True)
            
            if proc.returncode == 0:
                # Success path
                output_msg = (
                    f"{details}\n"
                    "-------------------------------------------------\n"
                    "PASSPHRASE UPDATED SUCCESSFULLY\n"
                    "-------------------------------------------------\n"
                    f"NEW PASSPHRASE: {new_passphrase}\n"
                    "=================================================\n"
                    "\nDo not loose this passphrase.\n"
                )
                dialog = KeyDetailsDialog(output_msg, title="Key Updated", parent=self)
                dialog.exec()
                self.log(f"Passphrase changed for {email}")
            else:
                # Failure path - Analyze error
                err_msg = proc.stderr
                self.log(f"Automated update failed: {err_msg}")
                
                if "invalid option" in err_msg or "usage" in err_msg:
                    # This suggests GPG 1.4 or missing feature. Fallback to Terminal.
                    reply = QMessageBox.question(
                        self, "Automation Failed",
                        "Automated passphrase update is not supported by your GPG version.\n\n"
                        "Would you like to open a terminal to change it manually?",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                    )
                    if reply == QMessageBox.StandardButton.Yes:
                        # Try to launch standard terminal emulators
                        terminals = ['x-terminal-emulator', 'konsole', 'gnome-terminal', 'xfce4-terminal', 'qterminal']
                        launched = False
                        for term in terminals:
                            if shutil.which(term):
                                # Launch interactive edit
                                subprocess.Popen([term, '-e', GPG_BIN, '--edit-key', fingerprint, 'passwd'])
                                launched = True
                                break
                        if not launched:
                            QMessageBox.warning(self, "Error", "Could not find a supported terminal emulator.")
                else:
                    QMessageBox.critical(self, "Error", f"Passphrase update failed. Check logs.\n{err_msg}")

        except Exception as e:
            QMessageBox.critical(self, "System Error", str(e))

    def menu_publish_key(self, request_email=False):
        
        email = None
        
        if request_email:
            email, ok = QInputDialog.getText(self, "Publish Key", "Enter Email Address of the key to publish:")
            if not ok or not email: return
        elif self.last_generated_email:
            email = self.last_generated_email
        else:
            QMessageBox.warning(self, "Publish Key", "No key has been generated in this session. Please use 'Publish Key by Email...'.")
            return

        details, fingerprint = self.get_key_details_block(email)
        if not fingerprint:
            QMessageBox.warning(self, "Error", f"Key for {email} not found locally.")
            return

        self.log(f"Attempting to publish key: {email} ({fingerprint})")
        
        # Start publishing to all keyservers sequentially
        self.publish_index = 0
        self.publish_results = []
        self.publish_key_sequence(fingerprint)

    def publish_key_sequence(self, fingerprint):
        if self.publish_index < len(KEYSERVERS):
            keyserver = KEYSERVERS[self.publish_index]
            self.log(f"Publishing to {keyserver}...")
            self.progress.show()
            
            self.publish_worker = GpgPublishWorker(fingerprint, keyserver)
            self.publish_worker.finished.connect(self.on_publish_finished)
            self.publish_worker.start()
        else:
            self.progress.hide()
            # Final result summary
            summary = "Key Publishing Complete:\n" + "\n".join(self.publish_results)
            QMessageBox.information(self, "Publish Result", summary)
            self.log("Key publishing sequence finished.")

    def on_publish_finished(self, success, message):
        self.log(message)
        self.publish_results.append(f"[{'SUCCESS' if success else 'FAILURE'}] {message.replace('Error: ', '')}")
        
        # Move to the next keyserver
        self.publish_index += 1
        self.publish_key_sequence(self.publish_worker.fingerprint)


    def menu_help(self):
        QMessageBox.information(self, "Help", 
            "GPG Key Generator Help\n\n"
            "1. Choose Quick (ECC) or Military (RSA) strength.\n"
            "2. Enter Name, Email, and Validity.\n"
            "3. Click 'Create'.\n\n"
            "The app handles key cleanup automatically if existing keys are found.\n"
            "Use 'Option -> Edit Key' to rotate your passphrase.\n\n"
            "Use 'Publish' to upload your public key to keyservers."
        )

    def menu_about(self):
        QMessageBox.information(self, "About", 
            "Gnoppix GPG Key Generator\n"
            "Target System: Gnoppix 26\n"
            "Version: 1.4\n\n"
            f"Using GPG Binary: {GPG_BIN}"
        )

    # -----------------------------------------------------
    # Creation Process
    # -----------------------------------------------------
    def start_creation_process(self):
        if not self.check_dependencies(): return

        name = self.input_name.text().strip()
        email = self.input_email.text().strip()
        validity = self.combo_validity.currentData()
        
        if not name or not email or not validity:
            QMessageBox.warning(self, "Missing Info", "Please fill in Name, Email and Validity.")
            return

        if not self.handle_existing_keys():
            self.log("Operation aborted by user.")
            return

        passphrase = secrets.token_hex(16) # 32 hex chars
        
        if self.radio_quick.isChecked():
            key_config = "Key-Type: eddsa\nKey-Curve: ed25519\nSubkey-Type: ecdh\nSubkey-Curve: curve25519"
        else:
            key_config = "Key-Type: RSA\nKey-Length: 4096\nSubkey-Type: RSA\nSubkey-Length: 4096"

        batch_content = f"""
%echo Generating OpenPGP key...
{key_config}
Name-Real: {name}
Name-Email: {email}
Name-Comment: {self.input_comment.text().strip()}
Expire-Date: {validity}
Passphrase: {passphrase}
%commit
%echo done
"""
        
        self.log("Starting GPG generation... (This may take a moment for entropy)")
        self.btn_create.setEnabled(False)
        self.progress.show()

        self.worker = GpgWorker(batch_content)
        # Pass all relevant details to the finished slot
        self.worker.finished.connect(lambda success, msg: self.on_generation_finished(success, msg, passphrase, email, name, validity))
        self.worker.start()

    def on_generation_finished(self, success, message, passphrase, email, name, validity):
        self.progress.hide()
        self.btn_create.setEnabled(True)
        self.log(message)
        
        # Set the last generated email for the "Publish Last Key" option
        self.last_generated_email = email

        if success:
            key_id, formatted_fpr = self.get_new_key_info(email)
            
            full_details = (
                "=================================================\n"
                "           GPG KEY DETAILS (SAVE SECURELY)       \n"
                "=================================================\n"
                f"Real Name:      {name}\n"
                f"Email:          {email}\n"
                f"Validity:       {self.combo_validity.currentText()} ({validity})\n"
                "-------------------------------------------------\n"
                f"Key ID:         {key_id}\n"
                f"Fingerprint:    {formatted_fpr}\n"
                "-------------------------------------------------\n"
                f"PASSPHRASE:     {passphrase}\n"
                "=================================================\n"
                "\n"
                "Please do not loose the passphrase.\n"
                "You need this always.\n"
            )
            
            self.log("Key Generation Successful. Opening details popup...")
            dialog = KeyDetailsDialog(full_details, title="Key Generated", parent=self)
            dialog.exec()
            
        else:
             # Clear last generated email if generation failed
             self.last_generated_email = None

    def get_new_key_info(self, email):
        try:
            # Use get_key_details_block to get fingerprint and ID
            details, fingerprint = self.get_key_details_block(email)
            
            if not fingerprint:
                 return "Error", "Error"
            
            # Extract key_id from the details string for simplicity (it's already formatted)
            key_id_match = re.search(r"Key ID:\s+([\d\w]+)", details)
            key_id = key_id_match.group(1) if key_id_match else "Unknown"
            
            # The get_key_details_block returns a formatted fingerprint, 
            # we need the unformatted one for the worker, but the formatted one 
            # for the output. Let's return the formatted one.
            fingerprint_match = re.search(r"Fingerprint:\s+([\d\w\s]+)", details)
            formatted_fpr = fingerprint_match.group(1) if fingerprint_match else "Error"
            
            return key_id, formatted_fpr
        except Exception:
            return "Error", "Error"

    def log(self, text):
        self.output_text.append(text)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = ModernGpgWizard()
    window.show()
    sys.exit(app.exec())
