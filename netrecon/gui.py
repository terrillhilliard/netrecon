"""A simple point-and-click launcher for netrecon (Tkinter, stdlib only).

`netrecon gui` opens a window with a button per common command. Each button
launches the command in its own terminal window so you see the output.
"""

from __future__ import annotations

import subprocess
import tkinter as tk

BG = "#0a1119"
BG2 = "#0c141d"
FG = "#c9f7e8"
DIM = "#3d5566"
NEON = "#00ffc3"
NEON2 = "#00e5ff"
RED = "#ff4d6d"

# (label, netrecon args, needs_admin, description)
BUTTONS = [
    ("🔍  Scan Network", "scan", False, "Discover hosts, open ports & versions, vendors"),
    ("🖥  Open Web Console", "serve", False, "Live dashboard in your browser (real data)"),
    ("🛡  Web Console (Admin)", "serve --monitor", True, "Dashboard + live capture / MITM — needs Administrator"),
    ("📋  Device Inventory", "hosts", False, "Everything discovered so far"),
    ("👁  Watch for New Devices", "watch", False, "Keep scanning; alert on new devices"),
    ("🌐  Traffic Flows", "flows", False, "Captured traffic (top talkers)"),
    ("🔌  Network Interfaces", "interfaces", False, "List adapters & the selected default"),
    ("❓  Help / All Commands", "--help", False, "Full command reference"),
]


def _run(args: str, admin: bool) -> None:
    if admin:
        # elevated new console (UAC prompt), keep window open with /k
        subprocess.Popen(
            ["powershell", "-NoProfile", "-Command",
             f"Start-Process cmd -Verb RunAs -ArgumentList '/k netrecon {args}'"],
            shell=False)
    else:
        subprocess.Popen(f'start "netrecon {args}" cmd /k netrecon {args}', shell=True)


def _mk_button(root, label, args, admin, desc):
    frame = tk.Frame(root, bg=BG)
    frame.pack(fill="x", padx=22, pady=(6, 0))
    accent = RED if admin else NEON
    b = tk.Button(frame, text=label, anchor="w", font=("Consolas", 13), fg=FG, bg=BG2,
                  activebackground="#12303f", activeforeground=accent, relief="flat", bd=0,
                  padx=16, pady=11, cursor="hand2", command=lambda: _run(args, admin))
    b.pack(fill="x")
    b.bind("<Enter>", lambda e: b.config(bg="#12303f", fg=accent))
    b.bind("<Leave>", lambda e: b.config(bg=BG2, fg=FG))
    tk.Label(root, text="    " + desc, font=("Consolas", 8), fg=DIM, bg=BG, anchor="w").pack(
        fill="x", padx=24)


def main() -> None:
    root = tk.Tk()
    root.title("netrecon")
    root.configure(bg=BG)
    root.geometry("460x600")
    root.minsize(420, 560)
    try:
        root.iconify(); root.deiconify()
    except Exception:
        pass

    tk.Label(root, text="◈ netrecon", font=("Consolas", 24, "bold"), fg=NEON, bg=BG).pack(pady=(22, 2))
    tk.Label(root, text="network reconnaissance & monitoring", font=("Consolas", 10),
             fg=DIM, bg=BG).pack(pady=(0, 16))

    for label, args, admin, desc in BUTTONS:
        _mk_button(root, label, args, admin, desc)

    tk.Label(root, text="tip: MITM / live capture need the Admin console (and wired Ethernet)",
             font=("Consolas", 8), fg=DIM, bg=BG, wraplength=420, justify="center").pack(
        side="bottom", pady=12)
    root.mainloop()


if __name__ == "__main__":
    main()
