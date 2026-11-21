[README.md](https://github.com/user-attachments/files/35219811/README.md)
# Device-Scam-Shield# 🛡️ On-Device Scam Shield

**A privacy-first, offline Python prototype that analyses suspicious SMS
messages, emails, chat text, and links.**

On-Device Scam Shield combines a small local **Multinomial Naive Bayes**
text classifier with explainable rule-based checks for suspicious words,
shortened URLs, external links, IP-address links, and requests for money
or authentication secrets.

> **Project:** PS-04  
> **Status:** Educational prototype  
> **Language:** Python 3.9+  
> **Interface:** Tkinter desktop GUI  
> **Dependencies:** Python standard library only

------------------------------------------------------------------------

## ✨ Features

- **Local message analysis:** The message is analysed on the device;
  this code does not upload message content to a server.
- **Machine-learning signal:** A small Multinomial Naive Bayes
  classifier is trained at startup using built-in example messages.
- **Explainable checks:** Suspicious terms and URL patterns contribute
  points to the risk index.
- **Risk categories:** Results are grouped into Lower Risk, Caution, and
  High Risk.
- **Safety guidance:** The app displays practical precautions based on
  the result.
- **Demo buttons:** Try built-in scam and safe message examples.
- **Simple desktop interface:** Dark-themed Tkinter interface with a
  risk bar, reasons, and recommendations.
- **No third-party packages:** Uses Python’s built-in libraries.

## 🖥️ Application Preview

When launched, the application provides: 1. A message input area. 2. An
**Analyse Message** button. 3. **Clear**, **Scam example**, and **Safe
example** controls. 4. A risk index from 0 to 100. 5. A list of detected
reasons and safety recommendations.

## 🧰 Built With

| Technology                | Purpose                              |
|---------------------------|--------------------------------------|
| Python                    | Main programming language            |
| Tkinter / ttk             | Desktop graphical user interface     |
| `math`                    | Logarithmic probability calculations |
| `re`                      | Token and URL pattern matching       |
| `urllib.parse`            | Parsing link hostnames               |
| `collections.Counter`     | Counting training words and labels   |
| `collections.defaultdict` | Storing per-class word counts        |

## 📋 Requirements

- Python **3.9 or newer**
- Tkinter (usually included with standard Python installations)
- Windows, macOS, or Linux desktop environment

No `pip install` command is required. If Tkinter is missing on Linux,
install the Tkinter package provided by your distribution.

## 🚀 Getting Started

### 1. Clone this repository

``` bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
cd YOUR-REPOSITORY
```

Replace `YOUR-USERNAME` and `YOUR-REPOSITORY` with your GitHub details.

### 2. Run the application

``` bash
python scam_shield.py
```

On some systems, use:

``` bash
python3 scam_shield.py
```

The desktop window should open. Paste a message and select **ANALYSE
MESSAGE**.

## 🧪 Try the Demo

Use the built-in **Scam example** and **Safe example** buttons to test
the application.

You can also paste your own sample text, for example:

``` text
URGENT: Your bank account is blocked. Verify now and share OTP
at http://bit.ly/example
```

The application will show a risk index, detected signals, and safety
recommendations.

## ⚙️ How It Works

The analysis follows these steps:

1.  **Input:** The user pastes or types a message.
2.  **Tokenization:** Text is converted to lowercase and split into
    alphanumeric tokens.
3.  **Naive Bayes analysis:** The local classifier compares the message
    with its built-in scam and legitimate examples.
4.  **Rule-based checks:** The program checks suspicious terms,
    shortened links, external links, raw IP-address links, and direct
    requests for OTP/PIN/money.
5.  **Risk index:** The model signal and rule points are combined and
    capped at 100.
6.  **Result:** A risk category, reasons, and safety advice are
    displayed.

### Risk Categories

| Risk index | Category       | Meaning                                                 |
|-----------:|----------------|---------------------------------------------------------|
|       0–39 | **LOWER RISK** | No strong indicators were detected by this prototype.   |
|      40–69 | **CAUTION**    | One or more suspicious indicators were detected.        |
|     70–100 | **HIGH RISK**  | Multiple or strong suspicious indicators were detected. |

**Important:** These are demonstration thresholds. The risk index is a
heuristic score, not a calibrated probability that a message is
fraudulent.

## 📁 Project Structure

``` text
.
├── scam_shield.py   # Main application, classifier, rules, and Tkinter UI
└── README.md        # Project documentation
```

If you add screenshots, tests, or other resources, you can create
folders such as `assets/` or `tests/`.

## 🔐 Privacy

- Message analysis is performed locally by this application.
- The code does not send message text to a remote server.
- The built-in training examples are stored in the Python source file.
- User-entered messages are not added to the training dataset.

This privacy description applies to this source code as provided. It
does not make claims about the operating system, the computer, or other
software running on the device.

## ⚠️ Limitations and Responsible Use

This project is an **educational prototype**, not a production-grade
fraud detection or cybersecurity product.

- The classifier is trained on only **40 hand-written demonstration
  messages** (20 scam and 20 legitimate).
- The dataset is small and cannot represent the variety of real-world
  scams or legitimate communication.
- The risk index is a heuristic demonstration score and is **not** a
  real-world fraud probability.
- A low score does not prove that a message or link is safe.
- URL checks inspect visible link patterns; the application does not
  open links, inspect website content, or verify a domain’s reputation.
- The app does not automatically access SMS, email, contacts, or
  notifications. The user must paste the message manually.
- False positives and false negatives are possible. Always verify
  unexpected requests through an official app, website, or trusted
  contact method.

Never share an OTP, PIN, password, or remote-access permission in
response to an unsolicited message.

## 🛠️ Possible Future Improvements

- Build a larger, carefully labelled dataset using consented and
  privacy-respecting examples.
- Evaluate the model with separate training and test sets and report
  precision, recall, and F1-score.
- Improve URL parsing and add safe, privacy-conscious reputation checks
  as an optional feature.
- Add multilingual scam-message detection.
- Add unit tests for tokenization, URL detection, scoring, and risk
  categories.
- Package the desktop application for easier installation.

## 🤝 Contributing

Contributions and suggestions are welcome.

1.  Fork the repository.
2.  Create a feature branch: `git checkout -b feature/your-feature`.
3.  Make your changes and test them.
4.  Commit your changes: `git commit -m "Add your feature"`.
5.  Push the branch and open a Pull Request.

Please avoid adding real personal messages or sensitive information to
sample datasets.

## 📄 License

No license has been specified yet. Add a `LICENSE` file before allowing
others to reuse, modify, or distribute this project. If you choose an
open-source license, select one that matches your goals.

------------------------------------------------------------------------

**Built as a student project — PS-04 \| On-Device Scam Shield**
