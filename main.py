import tkinter as tk
from tkinter import filedialog
from tkinter import messagebox
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import qrcode
import ctypes
from tkinter import ttk
from PIL import Image, ImageTk

class MainMenuApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Guardian")

        # Calculate screen dimensions
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        padding = 20

        # Set window dimensions and position
        window_width = 800
        window_height = 600
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.root.geometry(f"{window_width}x{window_height}+{x}+{y}")

        # Add padding to the root window
        self.root.geometry(f"{window_width - padding}x{window_height - padding}+{x + padding // 2}+{y + padding // 2}")

        self.key = None
        self.fernet = None

        # Add background image
        self.background_image = Image.open("bg.jpg")
        self.background_photo = ImageTk.PhotoImage(self.background_image)

        # Create a label for the background image
        background_label = tk.Label(self.root, image=self.background_photo)
        background_label.place(x=0, y=0, relwidth=1, relheight=1)  # Ensure the image covers the entire window

        self.frames = {}
        self.main_color = "#0072b1"

        # Style for buttons
        style = ttk.Style()
        style.configure("TButton",
                        relief=tk.RAISED,
                        background="lightblue",
                        font=("Helvetica", 12, 'italic', 'bold'),
                        foreground="navy")
        style.map("TButton",
                  background=[("active", "blue")])

        # Add button padding
        ctypes.windll.user32.SetProcessDPIAware()
        style.layout("TButton",
                     [('Button.button', {'children': [('Button.focus', {'children': [('Button.padding', {
                         'children': [('Button.label', {'side': 'left', 'expand': 'true'})],
                         'sticky': 'nswe'})], 'border': '2', 'sticky': 'nswe'})], 'sticky': 'nswe'})])

        self.create_main_menu()

    def create_main_menu(self):
        main_menu_frame = tk.Frame(self.root, bg=self.main_color)
        main_menu_frame.pack(fill="both", expand=True)

        # Load the background image for the main menu
        main_menu_bg_image = Image.open("bg.jpg")
        self.main_menu_bg_photo = ImageTk.PhotoImage(main_menu_bg_image)

        # Create a label for the background image and place it behind everything
        main_menu_bg_label = tk.Label(main_menu_frame, image=self.main_menu_bg_photo)
        main_menu_bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        functions_frame = tk.Frame(main_menu_frame, bg=self.main_color)
        functions_frame.pack(expand=True)

        # Define a custom style
        style = ttk.Style()
        style.configure("TButton", relief="raised", padding=(10, 5))

        # Center the title label in the middle of the functions_frame
        title = tk.Label(functions_frame, text="File Guardian", font=("Helvetica", 18, "italic", "bold"), pady=10,
                         bg=self.main_color, fg="yellow", relief=tk.RAISED, anchor='center', bd=4, padx=10)
        title.grid(row=0, column=0, columnspan=2, sticky="nsew")

        buttons = [
            ("Text Encryption/Decryption", self.open_text_encryption),
            ("Audio Encryption/Decryption", self.open_audio_encryption),
            ("Image Encryption/Decryption", self.open_image_encryption),
            ("Video Encryption/Decryption", self.open_video_encryption),
            ("File Encryption/Decryption", self.open_file_encryption),
            ("Generate QR Code", self.generate_qr_code)
        ]

        for i, (text, command) in enumerate(buttons):
            button = ttk.Button(
                functions_frame,
                text=text,
                command=command,
                style="TButton"
            )
            button.grid(row=i + 1, column=0, columnspan=2, sticky="nsew")  # Center-aligned buttons

        # Set row and column weights for centering
        for i in range(len(buttons) + 1):
            functions_frame.rowconfigure(i, weight=1)
        functions_frame.columnconfigure(0, weight=1)
        functions_frame.columnconfigure(1, weight=1)

        self.frames["main_menu"] = main_menu_frame

        # Rest of the code remains the same

    def open_text_encryption(self):
        current_frame = self.frames["main_menu"]
        current_frame.destroy()

        text_frame = tk.Frame(self.root, bg=self.main_color)  # Set background color here
        text_frame.pack(fill="both", expand=True, padx=150, pady=100)

        # Load the background image for the text encryption/decryption interface
        text_bg_image = Image.open("bg.jpg")
        self.text_bg_photo = ImageTk.PhotoImage(text_bg_image)

        # Create a label for the background image and place it behind everything
        text_bg_label = tk.Label(text_frame, image=self.text_bg_photo)
        text_bg_label.place(x=0, y=0, relwidth=1, relheight=1)

        title = tk.Label(text_frame, text="Text Encryption/Decryption", font=("Helvetica", 16, "bold italic"), padx=15,
                         pady=15)
        title.pack()

        text_input = tk.Text(text_frame, wrap=tk.WORD, width=40, height=10)
        text_input.pack(padx=10, pady=10)

        encrypt_button = tk.Button(text_frame, text="Encrypt Text", command=lambda: self.encrypt_text(text_input),
                                   bg="white", padx=10, pady=5, width=20)
        encrypt_button.pack(pady=5)

        decrypt_button = tk.Button(text_frame, text="Decrypt Text", command=lambda: self.decrypt_text(text_input),
                                   bg="white", padx=10, pady=5, width=20)
        decrypt_button.pack(pady=5)

        main_menu_button = tk.Button(text_frame, text="Go to Main Menu", command=self.go_to_main_menu, bg="white",
                                     padx=10, pady=5, width=20)
        main_menu_button.pack(pady=10)

        self.frames["text_encryption"] = text_frame
        self.set_current_frame("text_encryption")

    def open_audio_encryption(self):
        current_frame = self.frames["main_menu"]
        current_frame.destroy()

        audio_frame = tk.Frame(self.root, bg=self.main_color)
        audio_frame.pack(fill="both", expand=True, padx=150, pady=100)  # Adjust padding as needed

        title = tk.Label(audio_frame, text="Audio Encryption/Decryption", font=("Helvetica", 16, "italic", "bold"),
                         pady=10, bg=self.main_color, fg="yellow")
        title.grid(row=0, column=0, columnspan=2, sticky="nsew")

        select_audio_button = tk.Button(audio_frame, text="Select Audio File", command=self.select_audio,
                                        bg="white",
                                        padx=10, pady=5)
        select_audio_button.grid(row=1, column=0, columnspan=2, sticky="nsew")

        encrypt_audio_button = tk.Button(audio_frame, text="Encrypt Audio", command=self.encrypt_audio_file,
                                         bg="white",
                                         padx=10, pady=5)
        encrypt_audio_button.grid(row=2, column=0, columnspan=2, sticky="nsew")

        decrypt_audio_button = tk.Button(audio_frame, text="Decrypt Audio", command=self.decrypt_audio, bg="white",
                                         padx=10, pady=5)
        decrypt_audio_button.grid(row=3, column=0, columnspan=2, sticky="nsew")

        main_menu_button = tk.Button(audio_frame, text="Go to Main Menu", command=self.go_to_main_menu, bg="white",
                                     padx=10, pady=5)
        main_menu_button.grid(row=4, column=0, columnspan=2, sticky="nsew")

        # Set row and column weights for centering
        for i in range(5):
            audio_frame.rowconfigure(i, weight=1)
        audio_frame.columnconfigure(0, weight=1)
        audio_frame.columnconfigure(1, weight=1)

        self.frames["audio_encryption"] = audio_frame
        self.set_current_frame("audio_encryption")

    def select_audio(self):
        self.audio_path = filedialog.askopenfilename(filetypes=[("Audio files", "*.wav;*.mp3;*.ogg")])

        if self.audio_path:
            file_name = os.path.basename(self.audio_path)
            messagebox.showinfo("File Selected", f"{file_name} has been selected successfully.")

    def encrypt_audio_file(self):
        if self.fernet is None:
            self.load_or_generate_key()

        if self.audio_path:
            with open(self.audio_path, 'rb') as file:
                data = file.read()
                encrypted_data = self.fernet.encrypt(base64.b64encode(data))  # Encode data as base64

            output_path = filedialog.asksaveasfilename(defaultextension=".enc")
            if output_path:
                with open(output_path, 'wb') as output_file:
                    output_file.write(encrypted_data)
                    messagebox.showinfo("Encryption Result", "Audio encrypted and saved successfully.")

    def decrypt_audio(self):
        if self.fernet is None:
            self.load_or_generate_key()

        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Audio files", "*.enc")])
        if file_path:
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()
                    decrypted_data = base64.b64decode(self.fernet.decrypt(data))  # Decrypt and then decode

                output_path = filedialog.asksaveasfilename(defaultextension=".wav")
                if output_path:
                    with open(output_path, 'wb') as output_file:
                        output_file.write(decrypted_data)
                        messagebox.showinfo("Decryption Result", "Audio decrypted and saved successfully.")
            except InvalidToken:
                messagebox.showerror("Error", "Invalid token or incorrect key.")

    def open_image_encryption(self):
        current_frame = self.frames["main_menu"]
        current_frame.destroy()

        image_frame = tk.Frame(self.root, bg=self.main_color)
        image_frame.pack(fill="both", expand=True, padx=150, pady=100)  # Adjust padding

        title = tk.Label(image_frame, text="Image Encryption/Decryption", font=("Helvetica", 16, "italic", "bold"),
                         pady=10, bg=self.main_color, fg="yellow")
        title.grid(row=0, column=0, columnspan=2, sticky="nsew")

        select_image_button = tk.Button(image_frame, text="Select Image File", command=self.select_image, bg="white",
                                        padx=10, pady=5)
        select_image_button.grid(row=1, column=0, columnspan=2, sticky="nsew")

        encrypt_image_button = tk.Button(image_frame, text="Encrypt Image", command=self.encrypt_image_file, bg="white",
                                         padx=10, pady=5)
        encrypt_image_button.grid(row=2, column=0, columnspan=2, sticky="nsew")

        decrypt_image_button = tk.Button(image_frame, text="Decrypt Image", command=self.decrypt_image, bg="white",
                                         padx=10, pady=5)
        decrypt_image_button.grid(row=3, column=0, columnspan=2, sticky="nsew")

        main_menu_button = tk.Button(image_frame, text="Go to Main Menu", command=self.go_to_main_menu, bg="white",
                                     padx=10, pady=5)
        main_menu_button.grid(row=4, column=0, columnspan=2, sticky="nsew")

        for i in range(5):
            image_frame.rowconfigure(i, weight=1)
        image_frame.columnconfigure(0, weight=1)
        image_frame.columnconfigure(1, weight=1)

        self.frames["audio_encryption"] = image_frame
        self.set_current_frame("audio_encryption")

    def select_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.png;*.bmp")])

    def encrypt_image_file(self):
        if self.fernet is None:
            self.load_or_generate_key()

        if self.image_path:
            with open(self.image_path, 'rb') as file:
                data = file.read()
                encrypted_data = self.fernet.encrypt(data)

            output_path = filedialog.asksaveasfilename(defaultextension=".enc")
            if output_path:
                with open(output_path, 'wb') as output_file:
                    output_file.write(encrypted_data)
                    messagebox.showinfo("Encryption Result", "Image encrypted and saved successfully.")

    def decrypt_image(self):
        if self.fernet is None:
            self.load_or_generate_key()

        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Image files", "*.enc")])
        if file_path:
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()
                    decrypted_data = self.fernet.decrypt(data)

                output_path = filedialog.asksaveasfilename(defaultextension=".png")
                if output_path:
                    with open(output_path, 'wb') as output_file:
                        output_file.write(decrypted_data)
                        messagebox.showinfo("Decryption Result", "Image decrypted and saved successfully.")
            except InvalidToken:
                messagebox.showerror("Error", "Invalid token or incorrect key.")

    def open_video_encryption(self):
        current_frame = self.frames["main_menu"]
        current_frame.destroy()

        video_frame = tk.Frame(self.root, bg=self.main_color)
        video_frame.pack(fill="both", expand=True, padx=150, pady=100)

        title = tk.Label(video_frame, text="Video Encryption/Decryption", font=("Helvetica", 16, "italic", "bold"),
                         pady=10, bg=self.main_color, fg="yellow")
        title.grid(row=0, column=0, columnspan=2, sticky="nsew")

        select_video_button = tk.Button(video_frame, text="Select Video File", command=self.select_video, bg="white",
                                        padx=10, pady=5)
        select_video_button.grid(row=1, column=0, columnspan=2, sticky="nsew")

        encrypt_video_button = tk.Button(video_frame, text="Encrypt Video", command=self.encrypt_video_file, bg="white",
                                         padx=10, pady=5)
        encrypt_video_button.grid(row=2, column=0, columnspan=2, sticky="nsew")

        decrypt_video_button = tk.Button(video_frame, text="Decrypt Video", command=self.decrypt_video, bg="white",
                                         padx=10, pady=5)
        decrypt_video_button.grid(row=3, column=0, columnspan=2, sticky="nsew")

        main_menu_button = tk.Button(video_frame, text="Go to Main Menu", command=self.go_to_main_menu, bg="white",
                                     padx=10, pady=5)
        main_menu_button.grid(row=4, column=0, columnspan=2, sticky="nsew")

        for i in range(5):
            video_frame.rowconfigure(i, weight=1)
        video_frame.columnconfigure(0, weight=1)
        video_frame.columnconfigure(1, weight=1)

        self.frames["video_encryption"] = video_frame
        self.set_current_frame("video_encryption")

    def select_video(self):
            self.video_path = filedialog.askopenfilename(filetypes=[("Video files", "*.mp4;*.avi;*.mkv")])

            if self.video_path:
                file_name = os.path.basename(self.video_path)
                messagebox.showinfo("File Selected", f"{file_name} has been selected successfully.")

    def encrypt_video_file(self):
        if self.fernet is None:
            self.load_or_generate_key()

        if self.video_path:
            with open(self.video_path, 'rb') as file:
                data = file.read()
                encrypted_data = self.fernet.encrypt(data)

            output_path = filedialog.asksaveasfilename(defaultextension=".enc")
            if output_path:
                with open(output_path, 'wb') as output_file:
                    output_file.write(encrypted_data)
                    messagebox.showinfo("Encryption Result", "Video encrypted and saved successfully.")

    def decrypt_video(self):
        if self.fernet is None:
            self.load_or_generate_key()

        file_path = filedialog.askopenfilename(filetypes=[("Encrypted Video files", "*.enc")])
        if file_path:
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()
                    decrypted_data = self.fernet.decrypt(data)

                output_path = filedialog.asksaveasfilename(defaultextension=".mp4")
                if output_path:
                    with open(output_path, 'wb') as output_file:
                        output_file.write(decrypted_data)
                        messagebox.showinfo("Decryption Result", "Video decrypted and saved successfully.")
            except InvalidToken:
                messagebox.showerror("Error", "Invalid token or incorrect key.")

    def open_file_encryption(self):
        current_frame = self.frames["main_menu"]
        current_frame.destroy()

        file_frame = tk.Frame(self.root, bg=self.main_color)
        file_frame.pack(fill="both", expand=True, padx=150, pady=100)

        title = tk.Label(file_frame, text="File Encryption/Decryption", font=("Helvetica", 16, "italic", "bold"),
                         pady=10, bg=self.main_color, fg="yellow")
        title.grid(row=0, column=0, columnspan=2, sticky="nsew")

        select_file_button = tk.Button(file_frame, text="Select File", command=self.select_file, bg="white",
                                        padx=10, pady=5)
        select_file_button.grid(row=1, column=0, columnspan=2, sticky="nsew")


        encrypt_file_button = tk.Button(file_frame, text="Encrypt File", command=self.encrypt_file, bg="white",
                                         padx=10, pady=5)
        encrypt_file_button.grid(row=2, column=0, columnspan=2, sticky="nsew")

        decrypt_file_button = tk.Button(file_frame, text="Decrypt File", command=self.decrypt_file, bg="white",
                                         padx=10, pady=5)
        decrypt_file_button.grid(row=3, column=0, columnspan=2, sticky="nsew")

        main_menu_button = tk.Button(file_frame, text="Go to Main Menu", command=self.go_to_main_menu, bg="white",
                                     padx=10, pady=5)
        main_menu_button.grid(row=4, column=0, columnspan=2, sticky="nsew")

        # Set row and column weights for centering
        for i in range(5):
            file_frame.rowconfigure(i, weight=1)
        file_frame.columnconfigure(0, weight=1)
        file_frame.columnconfigure(1, weight=1)

        self.frames["file_encryption"] = file_frame
        self.set_current_frame("file_encryption")


    def select_file(self):
        self.file_path = filedialog.askopenfilename()

        if self.file_path:
            file_name = os.path.basename(self.file_path)
            messagebox.showinfo("File Selected", f"{file_name} has been selected successfully.")

    def encrypt_file(self):
        if self.fernet is None:
            self.load_or_generate_key()

        if self.file_path:
            with open(self.file_path, 'rb') as file:
                data = file.read()
                encrypted_data = self.fernet.encrypt(data)

            output_path = filedialog.asksaveasfilename(defaultextension=".enc")
            if output_path:
                with open(output_path, 'wb') as output_file:
                    output_file.write(encrypted_data)
                    messagebox.showinfo("Encryption Result", "File encrypted and saved successfully.")

    def decrypt_file(self):
        if self.fernet is None:
            self.load_or_generate_key()

        file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
        if file_path:
            try:
                with open(file_path, 'rb') as file:
                    data = file.read()
                    decrypted_data = self.fernet.decrypt(data)

                output_path = filedialog.asksaveasfilename()
                if output_path:
                    with open(output_path, 'wb') as output_file:
                        output_file.write(decrypted_data)
                        messagebox.showinfo("Decryption Result", "File decrypted and saved successfully.")
            except InvalidToken:
                messagebox.showerror("Error", "Invalid token or incorrect key.")

    def generate_qr_code(self):
        current_frame = self.frames["main_menu"]
        current_frame.destroy()

        qr_code_frame = tk.Frame(self.root)
        qr_code_frame.pack(fill="both", expand=True, padx=150, pady=100)  # Adjust padding

        title = tk.Label(qr_code_frame, text="Generate QR Code", font=("Helvetica", 16, "bold"), pady=10)
        title.pack()

        qr_label = tk.Label(qr_code_frame, text="Enter text to generate QR code:")
        qr_label.pack()

        qr_text = tk.Text(qr_code_frame, wrap=tk.WORD, width=40, height=10)
        qr_text.pack(padx=10, pady=10)

        generate_button = tk.Button(qr_code_frame, text="Generate QR Code",
                                    command=lambda: self.generate_qr(qr_text), bg="white", padx=10, pady=5)
        generate_button.pack(pady=5)

        main_menu_button = tk.Button(qr_code_frame, text="Go to Main Menu", command=self.go_to_main_menu,
                                     bg="white", padx=10, pady=5)
        main_menu_button.pack(pady=10)

        self.frames["generate_qr"] = qr_code_frame
        self.set_current_frame("generate_qr")

    def generate_qr(self, qr_text_widget):
        text = qr_text_widget.get("1.0", tk.END).strip()

        if not text:
            messagebox.showerror("Error", "Please enter text to generate QR code.")
            return

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(text)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        file_path = filedialog.asksaveasfilename(defaultextension=".png")
        if file_path:
            img.save(file_path)
            messagebox.showinfo("QR Code Generated", "QR code generated and saved successfully.")

    def go_to_main_menu(self):
        current_frame = self.frames[self.current_frame]
        current_frame.destroy()
        self.create_main_menu()

    def set_current_frame(self, frame_name):
        self.current_frame = frame_name

    def generate_key(self):
        password = "your_password_here".encode()  # Replace with a secure password
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            iterations=100000,
            salt=salt,
            length=32,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        self.key = key
        self.fernet = Fernet(key)

        # Save the key to a file
        key_file = "encryption_key.key"
        with open(key_file, 'wb') as file:
            file.write(key)

    def load_or_generate_key(self):
        key_file = "encryption_key.key"

        try:
            with open(key_file, 'rb') as file:
                key = file.read()
            self.key = key
            self.fernet = Fernet(key)
        except FileNotFoundError:
            self.generate_key()
        except InvalidToken:
            messagebox.showerror("Error", "Invalid token or incorrect key.")
    def encrypt_text(self, text_input_widget):
        if self.fernet is None:
            self.load_or_generate_key()

        plaintext = text_input_widget.get("1.0", tk.END).strip()
        plaintext = plaintext.encode()
        encrypted_text = self.fernet.encrypt(plaintext)
        text_input_widget.delete("1.0", tk.END)
        text_input_widget.insert(tk.END, encrypted_text.decode())

    def decrypt_text(self, text_input_widget):
        if self.fernet is None:
            self.load_or_generate_key()

        encrypted_text = text_input_widget.get("1.0", tk.END).strip()
        encrypted_text = encrypted_text.encode()
        try:
            decrypted_text = self.fernet.decrypt(encrypted_text)
            text_input_widget.delete("1.0", tk.END)
            text_input_widget.insert(tk.END, decrypted_text.decode())
        except InvalidToken:
            messagebox.showerror("Error", "Invalid token or incorrect key.")


if __name__ == "__main__":
    root = tk.Tk()
    app = MainMenuApp(root)
    root.mainloop()


