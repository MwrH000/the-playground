import tkinter as tk

# ---------- App Config ----------
BG_COLOR = "#0f172a"
FG_COLOR = "#e5e7eb"
ENTRY_BG = "#020617"
ACCENT = "#38bdf8"
ERROR = "#fb7185"

FONT_TITLE = ("Segoe UI", 14)
FONT_HINT = ("Segoe UI", 10)
FONT_ENTRY = ("Segoe UI", 18)
FONT_RESULT = ("Segoe UI", 24, "bold")
FONT_RESULT_LABEL = ("Segoe UI", 11)

# ---------- App ----------
root = tk.Tk()
root.title("Modern Calculator by @MwrH000")
root.geometry("420x300")
root.configure(bg=BG_COLOR)
root.resizable(False, False)

# ---------- Animation ----------
def animate_result(scale=0.7):
    if scale >= 1:
        result_value.config(font=FONT_RESULT)
        return
    size = int(24 * scale)
    result_value.config(font=("Segoe UI", size, "bold"))
    root.after(15, lambda: animate_result(scale + 0.05))


# ---------- Logic ----------
def calculate(event=None):
    expr = entry.get()
    try:
        allowed = "0123456789+-*/(). "
        if not all(c in allowed for c in expr):
            raise ValueError

        result = eval(expr)
        result_value.config(text=str(result), fg=ACCENT)
        animate_result()
    except:
        result_value.config(text="Invalid", fg=ERROR)
        animate_result()


def clear(event=None):
    entry.delete(0, tk.END)
    result_value.config(text="0", fg=FG_COLOR)


# ---------- UI ----------
title = tk.Label(
    root,
    text="Calculator",
    bg=BG_COLOR,
    fg=FG_COLOR,
    font=FONT_TITLE
)
title.pack(pady=(20, 4))

instruction = tk.Label(
    root,
    text="Type +  -  *  /   then press Enter • Esc to clear",
    bg=BG_COLOR,
    fg="#94a3b8",
    font=FONT_HINT
)
instruction.pack(pady=(0, 16))

entry = tk.Entry(
    root,
    font=FONT_ENTRY,
    bg=ENTRY_BG,
    fg=FG_COLOR,
    insertbackground=FG_COLOR,
    relief="flat",
    justify="center"
)
entry.pack(padx=30, pady=8, ipady=12, fill="x")
entry.focus()

result_label = tk.Label(
    root,
    text="RESULT",
    bg=BG_COLOR,
    fg="#94a3b8",
    font=FONT_RESULT_LABEL
)
result_label.pack(pady=(20, 2))

result_value = tk.Label(
    root,
    text="0",
    bg=BG_COLOR,
    fg=FG_COLOR,
    font=FONT_RESULT
)
result_value.pack()

# ---------- Key Bindings ----------
root.bind("<Return>", calculate)
root.bind("<Escape>", clear)

root.mainloop()
