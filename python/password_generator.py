import random
import string
import tkinter as tk
from tkinter import ttk


def generate_password(
    length=8, use_upper=True, use_lower=True, use_digits=True, use_symbols=True
):
    """Generate a random password with selected character groups."""
    characters = ""
    if use_upper:
        characters += string.ascii_uppercase
    if use_lower:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_symbols:
        characters += string.punctuation

    if not characters:
        return ""

    return "".join(random.choice(characters) for _ in range(length))


def _cli():
    print("Password Generator.")
    try:
        length = int(input("Enter password length (default 8): ") or 8)
        if length < 4:
            print("Password length should be at least 4 characters.")
        else:
            password = generate_password(length)
            print(f"Generated password: {password}")
    except ValueError:
        print("Invalid input. Using default length of 8.")
        password = generate_password()
        print(f"Generated password: {password}")
    finally:
        input("Press Enter to exit...")


def _build_ui():
    root = tk.Tk()
    root.title("Password Generator by @MwrH000")
    root.geometry("520x420")
    root.minsize(480, 380)
    root.configure(bg="#f4f6f8")

    style = ttk.Style(root)
    style.theme_use("clam")

    base_font = ("JetBrains Mono", 11)
    title_font = ("JetBrains Mono", 18, "bold")
    mono_font = ("JetBrains Mono", 12)

    style.configure(
        "TLabel", background="#f4f6f8", foreground="#1c1f23", font=base_font
    )
    style.configure("Title.TLabel", font=title_font)
    style.configure("Muted.TLabel", foreground="#5e6a75", font=base_font)
    style.configure("TCheckbutton", background="#f4f6f8", font=base_font)

    style.configure(
        "Primary.TButton",
        font=("JetBrains Mono", 11, "bold"),
        padding=10,
        background="#1f6feb",
        foreground="white",
    )
    style.map(
        "Primary.TButton",
        background=[("active", "#1a5fd0"), ("pressed", "#164fb0")],
        foreground=[("disabled", "#cfd7df")],
    )

    style.configure(
        "Secondary.TButton",
        font=("JetBrains Mono", 11),
        padding=10,
        background="#e6ebf1",
    )
    style.map("Secondary.TButton", background=[("active", "#d7dde5")])

    container = ttk.Frame(root, padding=26, style="TFrame")
    container.pack(fill="both", expand=True)

    title = ttk.Label(container, text="Password Generator", style="Title.TLabel")
    title.pack(anchor="w")

    subtitle = ttk.Label(
        container,
        text="Quickly create strong, random passwords.",
        style="Muted.TLabel",
    )
    subtitle.pack(anchor="w", pady=(4, 16))

    length_frame = ttk.Frame(container)
    length_frame.pack(fill="x")

    length_label = ttk.Label(length_frame, text="Length")
    length_label.pack(side="left")

    length_var = tk.IntVar(value=8)
    length_spin = ttk.Spinbox(
        length_frame,
        from_=4,
        to=64,
        textvariable=length_var,
        width=6,
        justify="center",
    )
    length_spin.pack(side="left", padx=(8, 0))

    output_label = ttk.Label(container, text="Generated password")
    output_label.pack(anchor="w", pady=(16, 6))

    output_var = tk.StringVar(value="")
    output_entry = ttk.Entry(container, textvariable=output_var, font=mono_font)
    output_entry.pack(fill="x", ipady=8)

    feedback_var = tk.StringVar(value="")
    feedback = ttk.Label(container, textvariable=feedback_var, style="Muted.TLabel")
    feedback.pack(anchor="w", pady=(6, 0))

    options_row = ttk.Frame(container)
    options_row.pack(fill="x", pady=(14, 0))

    use_upper_var = tk.BooleanVar(value=True)
    use_lower_var = tk.BooleanVar(value=True)
    use_digits_var = tk.BooleanVar(value=True)
    use_symbols_var = tk.BooleanVar(value=True)

    upper_cb = ttk.Checkbutton(options_row, text="Uppercase", variable=use_upper_var)
    lower_cb = ttk.Checkbutton(options_row, text="Lowercase", variable=use_lower_var)
    digits_cb = ttk.Checkbutton(options_row, text="Digits", variable=use_digits_var)
    symbols_cb = ttk.Checkbutton(options_row, text="Symbols", variable=use_symbols_var)

    upper_cb.pack(side="left", padx=(0, 10))
    lower_cb.pack(side="left", padx=(0, 10))
    digits_cb.pack(side="left", padx=(0, 10))
    symbols_cb.pack(side="left")

    strength_row = ttk.Frame(container)
    strength_row.pack(fill="x", pady=(12, 0))

    strength_label = ttk.Label(strength_row, text="Strength")
    strength_label.pack(side="left")

    strength_value_var = tk.StringVar(value="")
    strength_value = ttk.Label(strength_row, textvariable=strength_value_var)
    strength_value.pack(side="right")

    strength_bar = ttk.Progressbar(
        container, length=240, mode="determinate", maximum=100
    )
    strength_bar.pack(fill="x", pady=(6, 0))

    button_row = ttk.Frame(container)
    button_row.pack(fill="x", pady=(18, 0))

    def _estimate_strength(password, length, groups):
        if not password:
            return 0, "None"

        score = 0
        if length >= 8:
            score += 25
        if length >= 12:
            score += 15
        if length >= 16:
            score += 10
        score += min(40, groups * 10)
        score = min(100, score)

        if score < 30:
            label = "Weak"
        elif score < 50:
            label = "Moderate"
        elif score < 75:
            label = "Strong"
        else:
            label = "Very strong"

        return score, label

    def on_generate():
        length = length_var.get()
        if length < 4:
            feedback_var.set("Length must be at least 4 characters.")
            output_var.set("")
            strength_bar["value"] = 0
            strength_value_var.set("")
            return

        groups = sum(
            [
                use_upper_var.get(),
                use_lower_var.get(),
                use_digits_var.get(),
                use_symbols_var.get(),
            ]
        )

        password = generate_password(
            length=length,
            use_upper=use_upper_var.get(),
            use_lower=use_lower_var.get(),
            use_digits=use_digits_var.get(),
            use_symbols=use_symbols_var.get(),
        )

        if not password:
            feedback_var.set("Select at least one character type.")
            output_var.set("")
            strength_bar["value"] = 0
            strength_value_var.set("")
            return

        output_var.set(password)
        strength_score, strength_label_text = _estimate_strength(
            password, length, groups
        )
        strength_bar["value"] = strength_score
        strength_value_var.set(strength_label_text)
        feedback_var.set("Password generated.")

    def on_copy():
        password = output_var.get()
        if not password:
            feedback_var.set("Generate a password first.")
            return
        root.clipboard_clear()
        root.clipboard_append(password)
        feedback_var.set("Copied to clipboard.")

    generate_btn = ttk.Button(
        button_row,
        text="Generate",
        style="Primary.TButton",
        command=on_generate,
    )
    generate_btn.pack(side="left")

    copy_btn = ttk.Button(
        button_row,
        text="Copy",
        style="Secondary.TButton",
        command=on_copy,
    )
    copy_btn.pack(side="left", padx=(10, 0))

    output_entry.bind("<FocusIn>", lambda _event: output_entry.select_range(0, "end"))
    root.bind("<Return>", lambda _event: on_generate())

    root.mainloop()


if __name__ == "__main__":
    _build_ui()
