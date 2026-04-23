import requests
import tkinter as tk
from tkinter import scrolledtext, messagebox
import threading
import os
from dotenv import load_dotenv

load_dotenv()

class SimpleAIChat:
    def __init__(self, root):
        self.root = root
        self.root.title("AI Assistant")
        self.root.geometry("900x600")
        self.root.configure(bg='#1a1a1a')
        
        # Get API key from environment variable
        self.api_key = os.getenv('AIML_API_KEY', '')
        if not self.api_key:
            messagebox.showwarning(
                "API Key Missing", 
                "Please set your AIML_API_KEY in a .env file or environment variable."
            )
        
        # Simple dark colors
        self.bg = '#1a1a1a'
        self.input_bg = '#2d2d2d'
        self.text_color = '#e0e0e0'
        self.accent = '#10a37f'  # DeepSeek-like green
        
        # Configure grid weights
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        self.create_interface()
        
    def create_interface(self):
        # Simple header
        header = tk.Label(
            self.root,
            text="AI Chat",
            bg=self.bg,
            fg=self.accent,
            font=('Segoe UI', 16, 'bold')
        )
        header.grid(row=0, column=0, pady=(15, 5), padx=15, sticky='w')
        
        # Chat display area
        self.chat_area = scrolledtext.ScrolledText(
            self.root,
            wrap=tk.WORD,
            bg=self.input_bg,
            fg=self.text_color,
            font=('Segoe UI', 11),
            relief=tk.FLAT,
            borderwidth=0,
            padx=15,
            pady=15,
            height=20
        )
        self.chat_area.grid(row=1, column=0, padx=15, pady=(5, 10), sticky='nsew')
        self.chat_area.config(state=tk.DISABLED)
        
        # Input frame
        input_frame = tk.Frame(self.root, bg=self.bg)
        input_frame.grid(row=2, column=0, padx=15, pady=(0, 15), sticky='ew')
        input_frame.grid_columnconfigure(0, weight=1)
        
        # Text input
        self.input_field = tk.Text(
            input_frame,
            height=2,
            bg=self.input_bg,
            fg=self.text_color,
            font=('Segoe UI', 11),
            relief=tk.FLAT,
            borderwidth=0,
            padx=10,
            pady=10,
            insertbackground=self.accent
        )
        self.input_field.grid(row=0, column=0, sticky='ew')
        
        # Send button
        self.send_btn = tk.Button(
            input_frame,
            text="Send →",
            command=self.send_message,
            bg=self.accent,
            fg='white',
            font=('Segoe UI', 11, 'bold'),
            relief=tk.FLAT,
            cursor='hand2',
            padx=20,
            pady=8
        )
        self.send_btn.grid(row=0, column=1, padx=(10, 0))
        
        # Bind Enter key
        self.input_field.bind('<Return>', self.on_enter)
        self.input_field.bind('<Shift-Return>', lambda e: None)
        
        # Welcome message
        self.add_message("Assistant", "Hello! How can I help you today?")
        
    def on_enter(self, event):
        if not event.state & 0x1:  # Shift not pressed
            self.send_message()
            return 'break'
    
    def send_message(self):
        if not self.api_key:
            messagebox.showerror("Error", "API key not configured. Please check your .env file.")
            return
            
        user_input = self.input_field.get('1.0', 'end-1c').strip()
        
        if not user_input:
            return
        
        # Add user message
        self.add_message("You", user_input)
        
        # Clear input
        self.input_field.delete('1.0', tk.END)
        
        # Disable send button
        self.send_btn.config(state=tk.DISABLED, text="...")
        
        # Process in thread
        thread = threading.Thread(target=self.get_response, args=(user_input,))
        thread.daemon = True
        thread.start()
    
    def get_response(self, user_input):
        try:
            # Verify this is the correct endpoint for your API key
            response = requests.post(
                "https://api.aimlapi.com/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                json={
                    "model": "google/gemma-3-4b-it",  # Verify this model is available
                    "messages": [{"role": "user", "content": user_input}],
                    "temperature": 0.7,
                    "max_tokens": 10000,
                },
                timeout=30
            )
            
            response.raise_for_status()
            data = response.json()
            
            # Check if response has expected structure
            if "choices" in data and len(data["choices"]) > 0:
                answer = data["choices"][0]["message"]["content"]
                self.root.after(0, self.add_message, "Assistant", answer)
            else:
                self.root.after(0, self.add_message, "Assistant", f"Unexpected API response format: {data}")
            
        except requests.exceptions.Timeout:
            self.root.after(0, self.add_message, "Assistant", "Error: Request timed out. Please try again.")
        except requests.exceptions.HTTPError as e:
            if response.status_code == 401:
                self.root.after(0, self.add_message, "Assistant", "Error: Invalid API key. Please check your credentials.")
            elif response.status_code == 429:
                self.root.after(0, self.add_message, "Assistant", "Error: Rate limit exceeded. Please wait a moment.")
            else:
                self.root.after(0, self.add_message, "Assistant", f"HTTP Error: {e}")
        except Exception as e:
            self.root.after(0, self.add_message, "Assistant", f"Error: {str(e)}")
        
        finally:
            self.root.after(0, self.reset_button)
    
    def add_message(self, sender, message):
        self.chat_area.config(state=tk.NORMAL)
        
        # Add sender tag
        self.chat_area.insert(tk.END, f"{sender}: ", 'sender')
        
        # Configure tags
        self.chat_area.tag_config('sender', foreground=self.accent, font=('Segoe UI', 11, 'bold'))
        self.chat_area.tag_config('You', foreground=self.accent, font=('Segoe UI', 11, 'bold'))
        
        # Add message
        self.chat_area.insert(tk.END, f"{message}\n\n")
        
        # Auto-scroll
        self.chat_area.see(tk.END)
        self.chat_area.config(state=tk.DISABLED)
    
    def reset_button(self):
        self.send_btn.config(state=tk.NORMAL, text="Send →")

if __name__ == "__main__":
    root = tk.Tk()
    app = SimpleAIChat(root)
    root.mainloop()