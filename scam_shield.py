"""
On-Device Scam Shield — PS-04 prototype
Python 3.9+ | Standard library only | Offline after download/copy

This is an educational prototype, not a production fraud detector.
It trains a small Naive Bayes text classifier from local example data at
startup, combines the model score with explainable URL/social-engineering
signals, and never sends message content to a server.
"""
from __future__ import annotations
import math
import re
import tkinter as tk
from tkinter import ttk, messagebox
from urllib.parse import urlparse
from collections import Counter, defaultdict

# Small, locally stored demonstration corpus. Extend with consented, labelled
# examples for a real deployment. No user messages are used for training.
TRAINING_DATA = [
    ("scam", "Your bank account is blocked verify now using this link"),
    ("scam", "Congratulations you won a prize pay processing fee to claim"),
    ("scam", "Urgent KYC update required click link or account suspended"),
    ("scam", "Your parcel is held pay customs fee immediately"),
    ("scam", "Police case registered pay fine now to avoid arrest"),
    ("scam", "I am your son lost my phone send money to this new number"),
    ("scam", "Your electricity will be disconnected today pay bill here"),
    ("scam", "Investment guaranteed double return send money today"),
    ("scam", "Share OTP to receive refund and verify your identity"),
    ("scam", "Dear customer unusual activity login here to secure account"),
    ("scam", "You have been selected for a cash reward claim immediately"),
    ("scam", "Your SIM will be deactivated update details at this website"),
    ("scam", "Pay small fee now to release your package"),
    ("scam", "This is support team install remote access app for help"),
    ("scam", "Keep this confidential transfer money to safe account"),
    ("scam", "Your card is blocked call this number and share PIN"),
    ("scam", "Tax refund pending enter bank details to get refund"),
    ("scam", "Act now limited offer send deposit to reserve your prize"),
    ("scam", "We detected a problem click the shortened link and login"),
    ("scam", "Your wallet is frozen confirm password and one time code"),
    ("legit", "Your appointment is confirmed for tomorrow at ten am"),
    ("legit", "The library will remain closed on Sunday"),
    ("legit", "Your order has been shipped and is arriving Friday"),
    ("legit", "Hi are we still meeting for lunch at one"),
    ("legit", "Your monthly statement is ready in the official bank app"),
    ("legit", "Your electricity bill is available in the provider app"),
    ("legit", "The school meeting starts at four pm in room two"),
    ("legit", "Thanks for your payment your receipt is attached"),
    ("legit", "Please call me when you reach home"),
    ("legit", "Your parcel delivery is scheduled for tomorrow"),
    ("legit", "The event registration is confirmed thank you"),
    ("legit", "Your password was changed successfully if this was you"),
    ("legit", "Your subscription renews next month manage it in settings"),
    ("legit", "The train is delayed by fifteen minutes"),
    ("legit", "Your friend shared photos from the weekend"),
    ("legit", "Your report is ready for collection from the office"),
    ("legit", "The meeting agenda is attached for your review"),
    ("legit", "Your recharge was successful thank you"),
    ("legit", "Please review the class notes before tomorrow"),
    ("legit", "Your grocery order is ready for pickup"),
]

URL_RE = re.compile(r'(?i)\b(?:https?://|www\.)[^\s<>()]+')
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy"}
SUSPICIOUS_TERMS = {
    "urgent": 9, "immediately": 8, "otp": 18, "pin": 12, "password": 13,
    "blocked": 10, "suspended": 9, "verify": 7, "click": 6, "prize": 8,
    "winner": 8, "refund": 7, "transfer": 10, "confidential": 8,
    "arrest": 10, "deactivated": 9, "remote access": 14, "safe account": 12,
    "processing fee": 10, "limited time": 6, "act now": 7
}

def tokenize(text):
    return re.findall(r"[a-z0-9]+", text.lower())

class LocalNaiveBayes:
    """Tiny multinomial Naive Bayes text model; all computation is local."""
    def __init__(self):
        self.docs = Counter()
        self.words = defaultdict(Counter)
        self.vocab = set()

    def fit(self, rows):
        for label, text in rows:
            self.docs[label] += 1
            tokens = tokenize(text)
            self.words[label].update(tokens)
            self.vocab.update(tokens)

    def scam_probability(self, text):
        labels = ("scam", "legit")
        total_docs = sum(self.docs.values())
        vocab_size = max(1, len(self.vocab))
        scores = {}
        for label in labels:
            # Laplace-smoothed prior and token likelihood.
            score = math.log((self.docs[label] + 1) / (total_docs + 2))
            denom = sum(self.words[label].values()) + vocab_size
            for token in tokenize(text):
                score += math.log((self.words[label][token] + 1) / denom)
            scores[label] = score
        top = max(scores.values())
        probs = {k: math.exp(v - top) for k, v in scores.items()}
        return probs["scam"] / sum(probs.values())

MODEL = LocalNaiveBayes()
MODEL.fit(TRAINING_DATA)

def analyse_message(message):
    """Return risk 0-100, category, reasons, and safe next steps."""
    text = message.strip()
    if not text:
        return {"risk": 0, "level": "No message", "reasons": ["Enter a message to analyse."],
                "advice": ["Paste or type a message, then select Analyse."]}
    prob = MODEL.scam_probability(text)
    # Model probability is a signal, not a calibrated real-world probability.
    score = int(prob * 55)
    lower = text.lower()
    reasons = []
    for phrase, points in SUSPICIOUS_TERMS.items():
        if phrase in lower:
            score += points
            reasons.append(f"Pressure or sensitive-data signal: “{phrase}” (+{points})")
    urls = URL_RE.findall(text)
    for raw in urls:
        cleaned = raw.rstrip(".,!?;:)")
        host = urlparse(cleaned if cleaned.startswith("http") else "http://" + cleaned).netloc.lower()
        host = host.split("@")[-1].split(":")[0]
        if host in SHORTENERS:
            score += 18
            reasons.append(f"Shortened link hides its final destination: {host} (+18)")
        elif host and not any(host.endswith(x) for x in (".gov.in", ".gov", ".edu")):
            score += 5
            reasons.append(f"External link detected: {host} (+5); verify it independently")
        if re.search(r'(?i)(\d{1,3}\.){3}\d{1,3}', host):
            score += 15
            reasons.append("Link uses a raw IP address (+15)")
    # Multiple urgency/sensitive requests can indicate social engineering.
    if any(x in lower for x in ("send otp", "share otp", "share pin", "send money")):
        score += 15
        reasons.append("Direct request for money or authentication secret (+15)")
    score = min(100, score)
    if score >= 70:
        level = "HIGH RISK"
    elif score >= 40:
        level = "CAUTION"
    else:
        level = "LOWER RISK"
    if not reasons:
        reasons.append("No strong scam indicators were detected by this small demo model.")
    advice = []
    if score >= 40:
        advice = [
            "Do not click links or call numbers in the message.",
            "Never share OTP, PIN, password, or remote-access permissions.",
            "Verify using the official app, website, or a number you already trust.",
            "If money was lost, contact your bank immediately and report the incident."
        ]
    else:
        advice = [
            "Check the sender and context before acting.",
            "Open services through their official app or a saved bookmark.",
            "A low score does not prove a message is safe."
        ]
    return {"risk": score, "level": level, "reasons": reasons, "advice": advice}


class ScamShieldApp:
    BG = "#0b1220"
    PANEL = "#121d30"
    PANEL_ALT = "#17243a"
    TEXT = "#edf4ff"
    MUTED = "#91a4bf"
    CYAN = "#37d6d0"
    GREEN = "#42d392"
    AMBER = "#ffbf5b"
    RED = "#ff647c"

    def __init__(self, root):
        self.root = root
        self.root.title("SCAM SHIELD  |  Private Message Intelligence")
        self.root.geometry("1040x790")
        self.root.minsize(820, 680)
        self.root.configure(bg=self.BG)
        self.history = []
        self._build_styles()
        self._build_ui()
        self._load_demo()
        self.run_analysis()

    def _build_styles(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Shield.Horizontal.TProgressbar",
            troughcolor="#26354d",
            background=self.CYAN,
            bordercolor="#26354d",
            lightcolor=self.CYAN,
            darkcolor=self.CYAN,
            thickness=12,
        )
        style.configure(
            "Dark.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(13, 9),
            background=self.PANEL_ALT,
            foreground=self.TEXT,
            borderwidth=0,
        )
        style.map(
            "Dark.TButton",
            background=[("active", "#263a58"), ("pressed", "#20314b")],
            foreground=[("disabled", self.MUTED)],
        )
        style.configure(
            "Accent.TButton",
            font=("Segoe UI", 10, "bold"),
            padding=(15, 10),
            background=self.CYAN,
            foreground="#071521",
            borderwidth=0,
        )
        style.map("Accent.TButton", background=[("active", "#70eee7")])

    def _label(self, parent, text, size=10, color=None, bold=False, **kwargs):
        return tk.Label(
            parent, text=text, bg=kwargs.pop("bg", self.PANEL),
            fg=color or self.TEXT,
            font=("Segoe UI", size, "bold" if bold else "normal"),
            **kwargs
        )

    def _build_ui(self):
        outer = tk.Frame(self.root, bg=self.BG, padx=24, pady=20)
        outer.pack(fill="both", expand=True)

        header = tk.Frame(outer, bg=self.BG)
        header.pack(fill="x", pady=(0, 18))
        brand = tk.Frame(header, bg=self.BG)
        brand.pack(side="left", fill="x", expand=True)
        self._label(brand, "◈  SCAM SHIELD", 23, self.TEXT, True, bg=self.BG).pack(anchor="w")
        self._label(
            brand, "MESSAGE INTELLIGENCE  /  PRIVATE BY DESIGN", 9,
            self.CYAN, True, bg=self.BG
        ).pack(anchor="w", pady=(3, 0))
        privacy = tk.Frame(header, bg="#102c2b", padx=12, pady=8)
        privacy.pack(side="right", anchor="center")
        self._label(privacy, "●  ON-DEVICE MODE", 9, self.GREEN, True, bg="#102c2b").pack()

        # Main two-column workspace
        workspace = tk.Frame(outer, bg=self.BG)
        workspace.pack(fill="both", expand=True)
        workspace.columnconfigure(0, weight=3)
        workspace.columnconfigure(1, weight=2)
        workspace.rowconfigure(0, weight=1)

        left = tk.Frame(workspace, bg=self.PANEL, padx=18, pady=17,
                        highlightthickness=1, highlightbackground="#26354d")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        right = tk.Frame(workspace, bg=self.PANEL, padx=18, pady=17,
                         highlightthickness=1, highlightbackground="#26354d")
        right.grid(row=0, column=1, sticky="nsew")

        self._label(left, "Inspect a message", 16, self.TEXT, True).pack(anchor="w")
        self._label(
            left, "Paste an SMS, email, chat, or suspicious link below.",
            9, self.MUTED
        ).pack(anchor="w", pady=(4, 12))

        self.input = tk.Text(
            left, height=10, wrap="word", font=("Segoe UI", 11),
            bg="#0d1727", fg=self.TEXT, insertbackground=self.CYAN,
            selectbackground="#24536a", relief="flat", bd=0,
            padx=13, pady=12, highlightthickness=1,
            highlightbackground="#30435e", highlightcolor=self.CYAN
        )
        self.input.pack(fill="x", pady=(0, 12))

        buttons = tk.Frame(left, bg=self.PANEL)
        buttons.pack(fill="x")
        ttk.Button(
            buttons, text="⚡  ANALYSE MESSAGE", style="Accent.TButton",
            command=self.run_analysis
        ).pack(side="left")
        ttk.Button(
            buttons, text="Clear", style="Dark.TButton",
            command=self.clear
        ).pack(side="left", padx=(8, 0))

        examples = tk.Frame(left, bg=self.PANEL)
        examples.pack(fill="x", pady=(14, 0))
        self._label(examples, "TRY A DEMO", 8, self.MUTED, True).pack(side="left")
        ttk.Button(
            examples, text="Scam example", style="Dark.TButton",
            command=self._load_demo
        ).pack(side="right")
        ttk.Button(
            examples, text="Safe example", style="Dark.TButton",
            command=self.safe_example
        ).pack(side="right", padx=(0, 7))

        # Result panel
        self._label(right, "Threat assessment", 16, self.TEXT, True).pack(anchor="w")
        self._label(right, "A quick read of the message's risk signals.",
                    9, self.MUTED).pack(anchor="w", pady=(4, 15))

        self.status_card = tk.Frame(right, bg="#1b2b42", padx=14, pady=13)
        self.status_card.pack(fill="x")
        self.status = self._label(
            self.status_card, "READY TO SCAN", 10, self.CYAN, True,
            bg="#1b2b42"
        )
        self.status.pack(anchor="w")
        self.score = self._label(
            self.status_card, "—", 34, self.TEXT, True, bg="#1b2b42"
        )
        self.score.pack(anchor="w", pady=(3, 0))
        self._label(
            self.status_card, "RISK INDEX  /  100", 8, self.MUTED, True,
            bg="#1b2b42"
        ).pack(anchor="w", pady=(0, 10))
        self.bar = ttk.Progressbar(
            self.status_card, maximum=100, style="Shield.Horizontal.TProgressbar"
        )
        self.bar.pack(fill="x")

        self._label(right, "WHY IT GOT FLAGGED", 9, self.CYAN, True).pack(
            anchor="w", pady=(18, 7)
        )
        self.reasons = tk.Text(
            right, height=7, wrap="word", font=("Segoe UI", 9),
            bg="#0d1727", fg="#d9e6f7", relief="flat", bd=0,
            padx=10, pady=9, state="disabled"
        )
        self.reasons.pack(fill="both", expand=True)

        self._label(right, "YOUR SAFETY PLAYBOOK", 9, self.CYAN, True).pack(
            anchor="w", pady=(14, 7)
        )
        self.advice = tk.Text(
            right, height=6, wrap="word", font=("Segoe UI", 9),
            bg="#0d1727", fg="#d9e6f7", relief="flat", bd=0,
            padx=10, pady=9, state="disabled"
        )
        self.advice.pack(fill="both", expand=True)

        footer = tk.Frame(outer, bg=self.BG)
        footer.pack(fill="x", pady=(14, 0))
        self._label(
            footer,
            "🔒  LOCAL ANALYSIS ONLY   •   No message upload   •   No cloud processing",
            9, self.GREEN, True, bg=self.BG
        ).pack(side="left")
        self._label(
            footer, "EDUCATIONAL PROTOTYPE", 8, self.MUTED, True, bg=self.BG
        ).pack(side="right")

    def _load_demo(self):
        self.input.delete("1.0", "end")
        self.input.insert(
            "1.0",
            "URGENT: Your bank account is blocked. Verify now and share OTP "
            "at http://bit.ly/example"
        )
        self.run_analysis()

    def clear(self):
        self.input.delete("1.0", "end")
        self.status.config(text="READY TO SCAN", fg=self.CYAN)
        self.score.config(text="—", fg=self.TEXT)
        self.bar["value"] = 0
        self._set_text(self.reasons, "Add a message and select Analyse.")
        self._set_text(self.advice, "Your safety recommendations will appear here.")

    def safe_example(self):
        self.input.delete("1.0", "end")
        self.input.insert(
            "1.0",
            "Your appointment is confirmed for tomorrow at ten am. "
            "Please call me when you reach home."
        )
        self.run_analysis()

    def _set_text(self, widget, content):
        widget.config(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.config(state="disabled")

    def run_analysis(self):
        result = analyse_message(self.input.get("1.0", "end"))
        score = result["risk"]
        if score >= 70:
            color, banner = self.RED, "⚠  HIGH RISK"
        elif score >= 40:
            color, banner = self.AMBER, "◆  CAUTION"
        elif result["level"] == "No message":
            color, banner = self.CYAN, "○  WAITING FOR INPUT"
        else:
            color, banner = self.GREEN, "✓  LOWER RISK"

        self.status.config(text=banner, fg=color)
        self.score.config(text=f"{score:02d}", fg=color)
        self.bar["value"] = score
        self._set_text(
            self.reasons,
            "\n".join("•  " + item for item in result["reasons"])
        )
        self._set_text(
            self.advice,
            "\n".join("→  " + item for item in result["advice"])
        )
        if self.input.get("1.0", "end").strip():
            self.history.append(score)


if __name__ == "__main__":
    root = tk.Tk()
    ScamShieldApp(root)
    root.mainloop()
