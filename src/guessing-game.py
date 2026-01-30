import random
import tkinter as tk
import threading

try:
    import winsound
    SOUND = True
except:
    SOUND = False


BG = "#0f1115"
PANEL = "#161a22"
TEXT = "#e6e6e6"
MUTED = "#9aa0aa"
ACCENT = "#4f8cff"
GOOD = "#3ddc97"
WARN = "#ffcc66"
DANGER = "#ff6b6b"


def play_beep(freq=800, dur=120):
    if SOUND:
        threading.Thread(
            target=lambda: winsound.Beep(freq, dur),
            daemon=True
        ).start()
    else:
        root.bell()


class RoundedButton(tk.Canvas):
    def __init__(self, parent, text, command, w=140, h=40, r=18):
        super().__init__(parent, width=w, height=h, bg=BG, highlightthickness=0)
        self.command = command
        self.w = w
        self.h = h

        self.round_rect(0, 0, w, h, r, fill=ACCENT)
        self.create_text(
            w / 2, h / 2,
            text=text,
            fill="white",
            font=("Segoe UI", 11, "bold")
        )

        self.bind("<Button-1>", lambda e: self.command())
        self.bind("<Enter>", lambda e: self.scale("all", w/2, h/2, 1.05, 1.05))
        self.bind("<Leave>", lambda e: self.scale("all", w/2, h/2, 0.95, 0.95))

    def round_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1+r, y1,
            x2-r, y1,
            x2, y1,
            x2, y1+r,
            x2, y2-r,
            x2, y2,
            x2-r, y2,
            x1+r, y2,
            x1, y2,
            x1, y2-r,
            x1, y1+r,
            x1, y1
        ]
        return self.create_polygon(points, smooth=True, **kwargs)


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Guess")
        self.root.geometry("420x400")
        self.root.configure(bg=BG)
        self.root.resizable(False, False)

        self.levels = {
            "Easy": {"range": 20, "max_attempts": 10},
            "Medium": {"range": 50, "max_attempts": 7},
            "Hard": {"range": 100, "max_attempts": 5},
        }

        self.diff_var = tk.StringVar(value="Easy")
        self.range_max = self.levels["Easy"]["range"]
        self.max_attempts = self.levels["Easy"]["max_attempts"]

        self.secret = random.randint(1, self.range_max)
        self.attempts = 0
        self.animating = False

        self.container = tk.Frame(root, bg=BG)
        self.container.pack(expand=True)

        self.title = tk.Label(
            self.container,
            text="Guess the number",
            fg=TEXT,
            bg=BG,
            font=("Segoe UI", 18, "bold")
        )
        self.title.pack(pady=(25, 10))

        self.subtitle = tk.Label(
            self.container,
            text=f"1 – {self.range_max}",
            fg=MUTED,
            bg=BG,
            font=("Segoe UI", 11)
        )
        self.subtitle.pack()

        self.diff = tk.OptionMenu(
            self.container,
            self.diff_var,
            "Easy", "Medium", "Hard",
            command=self.change_difficulty
        )
        self.diff.configure(bg=PANEL, fg=TEXT, highlightthickness=0, borderwidth=0)
        self.diff["menu"].configure(bg=PANEL, fg=TEXT)
        self.diff.pack(pady=12)

        self.input = tk.Entry(
            self.container,
            bg=PANEL,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            font=("Segoe UI", 14),
            justify="center",
            width=10
        )
        self.input.pack(pady=10)
        self.input.focus()

        self.attempt_label = tk.Label(
            self.container,
            text=f"Attempts: 0 / {self.max_attempts}",
            fg=MUTED,
            bg=BG,
            font=("Segoe UI", 10)
        )
        self.attempt_label.pack()

        self.feedback = tk.Label(
            self.container,
            text="",
            fg=TEXT,
            bg=BG,
            font=("Segoe UI", 14, "bold"),
            justify="center"
        )
        self.feedback.pack(pady=12)

        self.button = RoundedButton(self.container, "Guess", self.check)
        self.button.pack(pady=10)

        self.reset = tk.Label(
            self.container,
            text="Reset",
            fg=MUTED,
            bg=BG,
            cursor="hand2",
            font=("Segoe UI", 10, "underline")
        )
        self.reset.pack()
        self.reset.bind("<Button-1>", lambda e: self.reset_game())

        self.root.bind("<Return>", lambda e: self.check())

    def pop_message(self, text, color, answer=None):
        if self.animating:
            self.animating = False

        self.animating = True

        if answer is not None:
            display = f"{text}\nThe answer is {answer}"
        else:
            display = text

        self.feedback.config(text=display, fg=color)

        sizes = [14, 18, 22, 18, 14]
        step = 0

        def animate():
            nonlocal step
            self.feedback.config(font=("Segoe UI", sizes[step], "bold"))
            step += 1
            if step < len(sizes):
                self.root.after(60, animate)
            else:
                self.animating = False

        animate()

    def change_difficulty(self, value):
        data = self.levels[value]
        self.range_max = data["range"]
        self.max_attempts = data["max_attempts"]
        self.subtitle.config(text=f"1 – {self.range_max}")
        self.reset_game()

    def check(self):
        value = self.input.get().strip()

        if not value.isdigit():
            play_beep(400)
            self.pop_message("Invalid input", WARN)
            return

        guess = int(value)
        self.attempts += 1
        self.attempt_label.config(
            text=f"Attempts: {self.attempts} / {self.max_attempts}"
        )

        if guess < self.secret:
            play_beep(600)
            self.pop_message("Too low", WARN)

        elif guess > self.secret:
            play_beep(600)
            self.pop_message("Too high", WARN)

        else:
            play_beep(1000)
            self.pop_message("Correct", GOOD, self.secret)
            self.root.after(1100, self.reset_game)
            self.input.delete(0, tk.END)
            return

        if self.attempts >= self.max_attempts:
            play_beep(300)
            self.pop_message("Out of attempts", DANGER, self.secret)
            self.root.after(1300, self.reset_game)

        self.input.delete(0, tk.END)

    def reset_game(self):
        self.secret = random.randint(1, self.range_max)
        self.attempts = 0
        self.attempt_label.config(
            text=f"Attempts: 0 / {self.max_attempts}"
        )
        self.feedback.config(text="", fg=TEXT)
        self.input.delete(0, tk.END)
        self.input.focus()


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()