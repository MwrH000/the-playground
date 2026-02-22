import os
import tkinter as tk
from tkinter import scrolledtext
from dotenv import load_dotenv
from google import genai

load_dotenv()

API_KEY = os.getenv('GEMINI_API_KEY')
MODEL_NAME = os.getenv('GEMINI_MODEL', 'models/gemini-2.0-flash')

if not API_KEY:
    print("ERROR: GEMINI_API_KEY tidak ditemukan di file .env!")
    print("Buat file .env dan isi dengan: GEMINI_API_KEY=api_key_anda")
    exit(1)

try:
    client = genai.Client(api_key=API_KEY)
    print("✅ API key valid!")
    print(f"📱 Menggunakan model: {MODEL_NAME}")
except Exception as e:
    print(f"❌ Error inisialisasi: {e}")
    exit(1)

class SimpleAI:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("🤖 AI Sederhana")
        self.window.geometry("500x600")
        
        self.bg_color = "#f5f5f5"
        self.window.configure(bg=self.bg_color)
        
        self.setup_ui()
        
        self.add_message("🤖 AI", f"Halo! Saya siap membantu.\nModel: {MODEL_NAME}")
    
    def setup_ui(self):
        header = tk.Frame(self.window, bg=self.bg_color)
        header.pack(pady=10)
        
        tk.Label(
            header,
            text="AI Sederhana dengan Gemini",
            font=("Arial", 16, "bold"),
            bg=self.bg_color
        ).pack()
        
        tk.Label(
            header,
            text=f"Model: {MODEL_NAME}",
            font=("Arial", 9),
            bg=self.bg_color,
            fg="gray"
        ).pack()
        
        self.chat = scrolledtext.ScrolledText(
            self.window,
            wrap=tk.WORD,
            width=60,
            height=25,
            font=("Arial", 10),
            bg="white",
            state="disabled"
        )
        self.chat.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        
        input_frame = tk.Frame(self.window, bg=self.bg_color)
        input_frame.pack(padx=10, pady=5, fill=tk.X)
        
        self.input_text = tk.Text(
            input_frame,
            height=3,
            width=50,
            font=("Arial", 10),
            bg="white"
        )
        self.input_text.pack(side=tk.LEFT, padx=5, fill=tk.BOTH, expand=True)
        
        self.input_text.bind('<Return>', self.on_enter)
        self.input_text.bind('<Shift-Return>', self.new_line)
        
        self.send_btn = tk.Button(
            input_frame,
            text="Kirim",
            command=self.send_message,
            bg="#4CAF50",
            fg="white",
            font=("Arial", 10, "bold"),
            padx=15,
            height=2
        )
        self.send_btn.pack(side=tk.RIGHT, padx=5)
        
        status_frame = tk.Frame(self.window, bg=self.bg_color)
        status_frame.pack(pady=5, fill=tk.X)
        
        self.status = tk.Label(
            status_frame,
            text="✅ Siap",
            font=("Arial", 9),
            bg=self.bg_color,
            fg="green"
        )
        self.status.pack(side=tk.LEFT, padx=10)
        
        tk.Button(
            status_frame,
            text="Bersihkan",
            command=self.clear_chat,
            bg="#f44336",
            fg="white",
            font=("Arial", 8),
            padx=10
        ).pack(side=tk.RIGHT, padx=10)
    
    def on_enter(self, event):
        self.send_message()
        return "break"
    
    def new_line(self, event):
        self.input_text.insert(tk.END, "\n")
        return "break"
    
    def add_message(self, sender, message):
        self.chat.config(state='normal')
        self.chat.insert(tk.END, f"{sender}: ", 'sender')
        self.chat.insert(tk.END, f"{message}\n\n")
        self.chat.tag_config('sender', font=('Arial', 10, 'bold'))
        self.chat.see(tk.END)
        self.chat.config(state='disabled')
    
    def send_message(self):
        user_input = self.input_text.get("1.0", tk.END).strip()
        
        if not user_input:
            return
        
        self.add_message("👤 Anda", user_input)
        self.input_text.delete("1.0", tk.END)
        
        self.status.config(text="⏳ AI sedang mengetik...", fg="orange")
        self.send_btn.config(state='disabled')
        
        self.window.after(100, lambda: self.get_response(user_input))
    
    def get_response(self, prompt):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt
            )
            
            ai_response = response.text
            self.add_message("🤖 AI", ai_response)
            
            self.status.config(text="✅ Siap", fg="green")
            
        except Exception as e:
            error_msg = f"Error: {str(e)}"
            self.add_message("⚠️ System", error_msg)
            self.status.config(text="❌ Error", fg="red")
        
        self.send_btn.config(state='normal')
    
    def clear_chat(self):
        self.chat.config(state='normal')
        self.chat.delete("1.0", tk.END)
        self.chat.config(state='disabled')
        self.add_message("🤖 AI", "Chat dibersihkan. Ada yang bisa saya bantu?")
    
    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    print("="*50)
    print("Memulai AI Sederhana...")
    print("="*50)
    
    app = SimpleAI()
    app.run()