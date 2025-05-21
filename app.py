import numpy as np
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json
from flask import Flask, request, jsonify
import requests
from kivy.app import App
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.filechooser import FileChooserListView
from kivy.core.clipboard import Clipboard
import threading
import time

# Flask App Setup
app = Flask(__name__)

def generate_aes256_key_from_params(params):
    param_bytes = np.array(params).tobytes()
    return hashlib.sha256(param_bytes).digest()

def encrypt_aes256(key, data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))
    return cipher.nonce, ciphertext, tag

def decrypt_aes256(key, nonce, ciphertext, tag):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')

def run_classical_optimization():
    # Simulated optimal parameters
    return np.array([0.12345, 0.12345, 0.12345, 0.12345])

@app.route('/')
def home():
    return jsonify({"status": "Server is running"})

@app.route('/encrypt', methods=['POST'])
def encrypt_message():
    data = request.get_json()
    message = data.get('message')
    if not message:
        return jsonify({"error": "Message is required"}), 400
    
    # Ensure message ends with a dot
    if not message.endswith('.'):
        message += '.'
    
    # Step 1: Run optimization
    optimal_params = run_classical_optimization()
    
    # Step 2: Derive key
    aes_key = generate_aes256_key_from_params(optimal_params)
    
    # Step 3: Encrypt message
    nonce, ciphertext, tag = encrypt_aes256(aes_key, message)
    
    # Step 4: Create bundle
    bundle = {
        "optimal_params": optimal_params.tolist(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "tag": base64.b64encode(tag).decode()
    }
    
    return jsonify(bundle), 200

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    bundle = request.get_json()
    
    try:
        # Step 1: Extract and decode data
        optimal_params = np.array(bundle["optimal_params"])
        nonce = base64.b64decode(bundle["nonce"])
        ciphertext = base64.b64decode(bundle["ciphertext"])
        tag = base64.b64decode(bundle["tag"])
        
        # Step 2: Derive key
        aes_key = generate_aes256_key_from_params(optimal_params)
        
        # Step 3: Decrypt and check marker
        decrypted_message = decrypt_aes256(aes_key, nonce, ciphertext, tag)
        response = {
            "message": decrypted_message[:-1] if decrypted_message.endswith('.') else decrypted_message,
            "dot_marker_found": decrypted_message.endswith('.')
        }
        if not response["dot_marker_found"]:
            response["warning"] = "No dot marker found. Message may be invalid or tampered."
        return jsonify(response), 200
    except Exception as e:
        return jsonify({"error": "Decryption failed! Possible tampering or key mismatch.", "details": str(e)}), 400

# Kivy UI
class EncryptionTab(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', padding=10, spacing=10, **kwargs)
        
        self.add_widget(Label(text="Alice's Encryption", font_size=20))
        self.message_input = TextInput(hint_text="Enter message to encrypt", multiline=True)
        self.add_widget(self.message_input)
        
        self.encrypt_button = Button(text="Encrypt", size_hint=(1, 0.2))
        self.encrypt_button.bind(on_press=self.encrypt)
        self.add_widget(self.encrypt_button)
        
        self.copy_button = Button(text="Copy Bundle", size_hint=(1, 0.2), disabled=True)
        self.copy_button.bind(on_press=self.copy_bundle)
        self.add_widget(self.copy_button)
        
        self.save_button = Button(text="Save Bundle to File", size_hint=(1, 0.2), disabled=True)
        self.save_button.bind(on_press=self.save_bundle)
        self.add_widget(self.save_button)
        
        self.result_label = Label(text="Result will appear here", size_hint=(1, 0.4))
        self.add_widget(self.result_label)
        
        self.bundle = None

    def encrypt(self, instance):
        message = self.message_input.text.strip()
        if not message:
            self.result_label.text = "Error: Please enter a message"
            return
        
        try:
            # Fixed: Added timeout=5
            response = requests.post('http://localhost:5000/encrypt', json={"message": message}, timeout=5)
            if response.status_code == 200:
                self.bundle = response.json()
                self.result_label.text = f"Bundle:\n{json.dumps(self.bundle, indent=2)}"
                self.copy_button.disabled = False
                self.save_button.disabled = False
            else:
                self.result_label.text = f"Error: {response.json().get('error', 'Unknown error')}"
        except requests.Timeout:
            self.result_label.text = "Error: Request timed out after 5 seconds"
        except requests.RequestException as e:
            self.result_label.text = f"Error: Failed to connect to server\n{str(e)}"

    def copy_bundle(self, instance):
        if self.bundle:
            Clipboard.copy(json.dumps(self.bundle, indent=2))
            self.result_label.text += "\nBundle copied to clipboard"

    def save_bundle(self, instance):
        if self.bundle:
            with open('for_bob.json', 'w') as f:
                json.dump(self.bundle, f)
            self.result_label.text += "\nSaved to for_bob.json"

class DecryptionTab(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation='vertical', padding=10, spacing=10, **kwargs)
        
        self.add_widget(Label(text="Bob's Decryption", font_size=20))
        
        self.bundle_input = TextInput(hint_text="Paste JSON bundle here", multiline=True)
        self.add_widget(self.bundle_input)
        
        self.paste_button = Button(text="Paste Bundle from Clipboard", size_hint=(1, 0.2))
        self.paste_button.bind(on_press=self.paste_bundle)
        self.add_widget(self.paste_button)
        
        self.file_chooser = FileChooserListView(size_hint=(1, 0.4), filters=['*.json'])
        self.add_widget(self.file_chooser)
        
        self.load_button = Button(text="Load Bundle from File", size_hint=(1, 0.2))
        self.load_button.bind(on_press=self.load_bundle)
        self.add_widget(self.load_button)
        
        self.decrypt_button = Button(text="Decrypt", size_hint=(1, 0.2))
        self.decrypt_button.bind(on_press=self.decrypt)
        self.add_widget(self.decrypt_button)
        
        self.result_label = Label(text="Result will appear here", size_hint=(1, 0.4))
        self.add_widget(self.result_label)

    def paste_bundle(self, instance):
        try:
            pasted_text = Clipboard.paste()
            json.loads(pasted_text)  # Validate JSON
            self.bundle_input.text = pasted_text
            self.result_label.text = "Bundle pasted from clipboard"
        except json.JSONDecodeError:
            self.result_label.text = "Error: Invalid JSON in clipboard"
        except Exception as e:
            self.result_label.text = f"Error pasting from clipboard: {str(e)}"

    def load_bundle(self, instance):
        selected = self.file_chooser.selection
        if selected:
            try:
                with open(selected[0], 'r') as f:
                    self.bundle_input.text = json.dumps(json.load(f), indent=2)
                self.result_label.text = "Bundle loaded from file"
            except Exception as e:
                self.result_label.text = f"Error loading file: {str(e)}"

    def decrypt(self, instance):
        try:
            bundle = json.loads(self.bundle_input.text)
            # Fixed: Added timeout=5
            response = requests.post('http://localhost:5000/decrypt', json=bundle, timeout=5)
            if response.status_code == 200:
                result = response.json()
                message = result['message']
                dot_marker = result['dot_marker_found']
                warning = result.get('warning', '')
                self.result_label.text = f"Decrypted Message: {message}\nDot Marker Found: {dot_marker}"
                if warning:
                    self.result_label.text += f"\nWarning: {warning}"
            else:
                self.result_label.text = f"Error: {response.json().get('error', 'Unknown error')}"
        except requests.Timeout:
            self.result_label.text = "Error: Request timed out after 5 seconds"
        except (json.JSONDecodeError, requests.RequestException) as e:
            self.result_label.text = f"Error: Invalid bundle or server error\n{str(e)}"

class CryptoApp(TabbedPanel):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.do_default_tab = False
        
        encrypt_tab = TabbedPanelItem(text="Encrypt")
        encrypt_tab.add_widget(EncryptionTab())
        self.add_widget(encrypt_tab)
        
        decrypt_tab = TabbedPanelItem(text="Decrypt")
        decrypt_tab.add_widget(DecryptionTab())
        self.add_widget(decrypt_tab)

class MainApp(App):
    def build(self):
        return CryptoApp()

if __name__ == '__main__':
    # Start Flask in a separate thread for development only
    flask_thread = threading.Thread(target=lambda: app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False), daemon=True)
    flask_thread.start()
    # Give Flask time to start
    time.sleep(1)
    # Run Kivy app
    MainApp().run()
