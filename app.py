from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_mysqldb import MySQL
from werkzeug.security import check_password_hash, generate_password_hash
import MySQLdb.cursors
import json
import os, re, uuid, hashlib, pickle
import pandas as pd
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
from urllib.request import Request, urlopen

app = Flask(__name__)

def load_local_env(path=".env"):
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8") as env_file:
        for line in env_file:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())

load_local_env()

app.secret_key = os.getenv('SECRET_KEY', 'your_secret_key')

# MySQL Config
app.config['MYSQL_HOST'] = os.getenv('DB_HOST', 'localhost')
app.config['MYSQL_USER'] = os.getenv('DB_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('DB_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('DB_NAME', 'phishing_db')

mysql = MySQL(app)
SAFE_BROWSING_API_KEY = os.getenv("SAFE_BROWSING_API_KEY", "").strip()

def hash_password(password):
    return generate_password_hash(password)

def legacy_hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def password_matches(stored_hash, password):
    if not stored_hash:
        return False
    if stored_hash == legacy_hash_password(password):
        return True
    try:
        return check_password_hash(stored_hash, password)
    except ValueError:
        return False

def is_legacy_hash(stored_hash):
    return bool(re.fullmatch(r"[a-f0-9]{64}", stored_hash or ""))

def get_cursor(dict_cursor=False):
    try:
        cursor_type = MySQLdb.cursors.DictCursor if dict_cursor else None
        return mysql.connection.cursor(cursor_type) if cursor_type else mysql.connection.cursor()
    except MySQLdb.OperationalError:
        app.logger.exception("MySQL connection failed")
        return None

def is_main_user():
    return session.get('username') == 'main'

def ensure_support_columns(cursor):
    missing_columns = {
        'requester_name': 'ALTER TABLE support_requests ADD COLUMN requester_name VARCHAR(100)',
        'contact_email': 'ALTER TABLE support_requests ADD COLUMN contact_email VARCHAR(100)',
        'admin_response': 'ALTER TABLE support_requests ADD COLUMN admin_response TEXT',
        'resolved_at': 'ALTER TABLE support_requests ADD COLUMN resolved_at DATETIME NULL'
    }
    for column_name, alter_sql in missing_columns.items():
        cursor.execute('SHOW COLUMNS FROM support_requests LIKE %s', (column_name,))
        if cursor.fetchone() is None:
            cursor.execute(alter_sql)
            mysql.connection.commit()

def format_support_tickets(tickets):
    formatted_tickets = []
    subject_pattern = re.compile(r"^Support request from\s+(.+?)(?:\s+<([^>]+)>)?$")
    for ticket in tickets:
        ticket_data = dict(ticket)
        subject = ticket_data.get('subject') or ''
        match = subject_pattern.match(subject)
        requester_name = ticket_data.get('requester_name') or ticket_data.get('username') or 'Unknown'
        contact_email = ticket_data.get('contact_email') or ticket_data.get('account_email') or ''

        if match:
            requester_name = match.group(1).strip() or requester_name
            contact_email = (match.group(2) or contact_email).strip()

        ticket_data['requester_name'] = requester_name
        ticket_data['contact_email'] = contact_email
        formatted_tickets.append(ticket_data)
    return formatted_tickets

ml_model = None
model_load_error = None
try:
    with open("model.pkl", "rb") as f:
        ml_model = pickle.load(f)
except (FileNotFoundError, EOFError, pickle.UnpicklingError) as exc:
    model_load_error = exc

def normalize_url(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

BRAND_DOMAINS = {
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "apple": {"apple.com"},
    "coursera": {"coursera.org"},
    "facebook": {"facebook.com"},
    "google": {"google.com"},
    "instagram": {"instagram.com"},
    "meesho": {"meesho.com"},
    "microsoft": {"microsoft.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
    "udemy": {"udemy.com"},
}

LOOKALIKE_TRANSLATION = str.maketrans({
    "0": "o",
    "1": "l",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "@": "a",
    "$": "s",
})

def get_domain(url):
    return urlparse(normalize_url(url)).hostname or ""

def is_official_brand_domain(domain):
    domain = domain.lower().strip(".")
    return any(
        domain == official or domain.endswith("." + official)
        for official_domains in BRAND_DOMAINS.values()
        for official in official_domains
    )

def is_deceptive_brand_domain(domain):
    domain = domain.lower().strip(".")
    labels = [label for label in domain.split(".") if label]

    for label in labels:
        normalized_label = label.translate(LOOKALIKE_TRANSLATION)
        for brand, official_domains in BRAND_DOMAINS.items():
            if normalized_label == brand and not is_official_brand_domain(domain):
                return True
    return False

def check_safe_browsing(url):
    if not SAFE_BROWSING_API_KEY:
        return None

    endpoint = (
        "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        f"?key={SAFE_BROWSING_API_KEY}"
    )
    payload = {
        "client": {
            "clientId": "phishguard-local",
            "clientVersion": "1.0",
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        request_data = json.dumps(payload).encode("utf-8")
        req = Request(
            endpoint,
            data=request_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8") or "{}")
        return bool(data.get("matches"))
    except Exception as exc:
        app.logger.warning("Safe Browsing check failed: %s", exc)
        return None

def has_ip_address(domain):
    return bool(re.fullmatch(r"\d+\.\d+\.\d+\.\d+", domain))

def count_subdomains(domain):
    parts = domain.split(".")
    return len(parts) - 2 if len(parts) > 2 else 0

def same_domain(url, base_domain):
    domain = get_domain(url)
    return domain == base_domain or domain.endswith("." + base_domain)

class PageFeatureParser(HTMLParser):
    def __init__(self, page_url):
        super().__init__()
        self.page_url = page_url
        self.page_domain = get_domain(page_url).lower()
        self.in_title = False
        self.title_parts = []
        self.has_title = 0
        self.has_favicon = 0
        self.is_responsive = 0
        self.has_description = 0
        self.no_of_popup = 0
        self.no_of_iframe = 0
        self.has_external_form_submit = 0
        self.has_social_net = 0
        self.has_submit_button = 0
        self.has_hidden_fields = 0
        self.has_password_field = 0
        self.has_copyright_info = 0
        self.no_of_image = 0
        self.no_of_css = 0
        self.no_of_js = 0
        self.no_of_self_ref = 0
        self.no_of_empty_ref = 0
        self.no_of_external_ref = 0

    def handle_starttag(self, tag, attrs):
        attrs = {key.lower(): (value or "") for key, value in attrs}
        tag = tag.lower()

        if tag == "title":
            self.in_title = True
            self.has_title = 1
        elif tag == "meta":
            name = attrs.get("name", "").lower()
            content = attrs.get("content", "").lower()
            if name == "description" and content:
                self.has_description = 1
            if attrs.get("name", "").lower() == "viewport":
                self.is_responsive = 1
        elif tag == "link":
            rel = attrs.get("rel", "").lower()
            href = attrs.get("href", "")
            if "icon" in rel:
                self.has_favicon = 1
            if "stylesheet" in rel:
                self.no_of_css += 1
            self.count_reference(href)
        elif tag == "script":
            self.no_of_js += 1
            self.count_reference(attrs.get("src", ""))
        elif tag == "img":
            self.no_of_image += 1
            self.count_reference(attrs.get("src", ""))
        elif tag in {"a", "area"}:
            self.count_reference(attrs.get("href", ""))
        elif tag == "form":
            action = attrs.get("action", "")
            if action and not same_domain(urljoin(self.page_url, action), self.page_domain):
                self.has_external_form_submit = 1
        elif tag == "input":
            input_type = attrs.get("type", "").lower()
            if input_type == "submit":
                self.has_submit_button = 1
            elif input_type == "hidden":
                self.has_hidden_fields = 1
            elif input_type == "password":
                self.has_password_field = 1
        elif tag == "button":
            if attrs.get("type", "").lower() in {"", "submit"}:
                self.has_submit_button = 1
        elif tag == "iframe":
            self.no_of_iframe += 1

        joined_attrs = " ".join(attrs.values()).lower()
        if "popup" in joined_attrs or "window.open" in joined_attrs:
            self.no_of_popup += 1
        if any(site in joined_attrs for site in ["facebook.com", "instagram.com", "x.com", "twitter.com", "linkedin.com"]):
            self.has_social_net = 1

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data.strip())
        if "copyright" in data.lower():
            self.has_copyright_info = 1

    def count_reference(self, ref):
        ref = (ref or "").strip()
        if not ref or ref in {"#", "/#"} or ref.lower().startswith(("javascript:", "mailto:", "tel:")):
            self.no_of_empty_ref += 1
            return

        absolute_ref = urljoin(self.page_url, ref)
        if same_domain(absolute_ref, self.page_domain):
            self.no_of_self_ref += 1
        else:
            self.no_of_external_ref += 1

def fetch_page_features(url):
    defaults = {
        "LineOfCode": 0,
        "LargestLineLength": 0,
        "HasTitle": 0,
        "DomainTitleMatchScore": 0,
        "URLTitleMatchScore": 0,
        "HasFavicon": 0,
        "Robots": 0,
        "IsResponsive": 0,
        "HasDescription": 0,
        "NoOfPopup": 0,
        "NoOfiFrame": 0,
        "HasExternalFormSubmit": 0,
        "HasSocialNet": 0,
        "HasSubmitButton": 0,
        "HasHiddenFields": 0,
        "HasPasswordField": 0,
        "HasCopyrightInfo": 0,
        "NoOfImage": 0,
        "NoOfCSS": 0,
        "NoOfJS": 0,
        "NoOfSelfRef": 0,
        "NoOfEmptyRef": 0,
        "NoOfExternalRef": 0,
    }

    try:
        req = Request(url, headers={"User-Agent": "Mozilla/5.0 PhishGuardScanner/1.0"})
        with urlopen(req, timeout=5) as response:
            html = response.read(1_500_000).decode("utf-8", errors="ignore")
    except Exception:
        return defaults

    parser = PageFeatureParser(url)
    try:
        parser.feed(html)
    except Exception:
        pass

    title = " ".join(part for part in parser.title_parts if part).lower()
    domain = get_domain(url).lower()
    domain_name = domain.split(".")[-2] if "." in domain else domain
    line_lengths = [len(line) for line in html.splitlines()] or [0]

    defaults.update({
        "LineOfCode": len(line_lengths),
        "LargestLineLength": max(line_lengths),
        "HasTitle": parser.has_title,
        "DomainTitleMatchScore": 100 if domain_name and domain_name in title else 0,
        "URLTitleMatchScore": 100 if title and any(part in title for part in domain.split(".")) else 0,
        "HasFavicon": parser.has_favicon,
        "IsResponsive": parser.is_responsive,
        "HasDescription": parser.has_description,
        "NoOfPopup": parser.no_of_popup,
        "NoOfiFrame": parser.no_of_iframe,
        "HasExternalFormSubmit": parser.has_external_form_submit,
        "HasSocialNet": parser.has_social_net,
        "HasSubmitButton": parser.has_submit_button,
        "HasHiddenFields": parser.has_hidden_fields,
        "HasPasswordField": parser.has_password_field,
        "HasCopyrightInfo": parser.has_copyright_info,
        "NoOfImage": parser.no_of_image,
        "NoOfCSS": parser.no_of_css,
        "NoOfJS": parser.no_of_js,
        "NoOfSelfRef": parser.no_of_self_ref,
        "NoOfEmptyRef": parser.no_of_empty_ref,
        "NoOfExternalRef": parser.no_of_external_ref,
    })

    robots_url = f"{urlparse(url).scheme}://{domain}/robots.txt"
    try:
        req = Request(robots_url, headers={"User-Agent": "Mozilla/5.0 PhishGuardScanner/1.0"})
        with urlopen(req, timeout=2) as response:
            defaults["Robots"] = 1 if response.status < 400 else 0
    except Exception:
        defaults["Robots"] = 0

    return defaults

LEGACY_FEATURE_NAMES = [
    "having_IP_Address",
    "URL_Length",
    "Shortining_Service",
    "having_At_Symbol",
    "double_slash_redirecting",
    "Prefix_Suffix",
    "having_Sub_Domain",
    "SSLfinal_State",
    "Domain_registeration_length",
    "Favicon",
    "port",
    "HTTPS_token",
    "Request_URL",
    "URL_of_Anchor",
    "Links_in_tags",
    "SFH",
    "Submitting_to_email",
    "Abnormal_URL",
    "Redirect",
    "on_mouseover",
    "RightClick",
    "popUpWidnow",
    "Iframe",
    "age_of_domain",
    "DNSRecord",
    "web_traffic",
    "Page_Rank",
    "Google_Index",
    "Links_pointing_to_page",
    "Statistical_report",
]

def extract_legacy_features(url):
    url = normalize_url(url)
    domain = get_domain(url).lower()
    full_url = url.lower()
    redirect_count = full_url.count("//") - 1
    suspicious_words = ["login", "verify", "secure", "account", "update", "bank", "signin"]

    features = [
        1 if has_ip_address(domain) else -1,
        1 if len(url) >= 75 else (0 if len(url) >= 54 else -1),
        1 if any(shortener in domain for shortener in ["bit.ly", "tinyurl", "goo.gl", "t.co"]) else -1,
        1 if "@" in url else -1,
        1 if redirect_count > 0 else -1,
        1 if "-" in domain else -1,
        1 if count_subdomains(domain) > 2 else (0 if count_subdomains(domain) == 1 else -1),
        -1 if full_url.startswith("https://") else 1,
        0,
        1 if "favicon" in full_url else -1,
        1 if ":" in domain else -1,
        1 if "https" in domain else -1,
        0,
        0,
        0,
        0,
        1 if "mailto:" in full_url else -1,
        1 if any(word in full_url for word in suspicious_words) else -1,
        1 if redirect_count > 1 else -1,
        1 if "onmouseover" in full_url else -1,
        1 if "contextmenu" in full_url else -1,
        1 if "popup" in full_url else -1,
        1 if "iframe" in full_url else -1,
        0,
        0,
        0,
        0,
        0,
        0,
        1 if any(tld in domain for tld in [".ru", ".tk", ".ml", ".ga", ".cf"]) else -1
    ]
    return features

def extract_feature_values(url):
    url = normalize_url(url)
    domain = get_domain(url).lower()
    full_url = url.lower()
    legacy_features = extract_legacy_features(url)
    values = dict(zip(LEGACY_FEATURE_NAMES, legacy_features))
    suspicious_words = ["login", "verify", "secure", "account", "update", "bank", "signin"]
    special_chars = sum(1 for char in url if not char.isalnum())
    letters = sum(1 for char in url if char.isalpha())
    digits = sum(1 for char in url if char.isdigit())
    redirects = max(full_url.count("//") - 1, 0)
    query = urlparse(url).query

    values.update({
        "URLLength": len(url),
        "DomainLength": len(domain),
        "IsDomainIP": 1 if has_ip_address(domain) else 0,
        "URLSimilarityIndex": 100 if is_official_brand_domain(domain) else 35 if is_deceptive_brand_domain(domain) else 70,
        "CharContinuationRate": 1 if "-" not in domain else 0,
        "TLDLegitimateProb": 0.1 if domain.endswith((".ru", ".tk", ".ml", ".ga", ".cf")) else 0.5,
        "URLCharProb": min(1, max(0, len(set(url)) / max(len(url), 1))),
        "TLDLength": len(domain.rsplit(".", 1)[-1]) if "." in domain else 0,
        "NoOfSubDomain": max(count_subdomains(domain), 0),
        "HasObfuscation": 1 if any(char in url for char in ["@", "%", "\\"]) else 0,
        "NoOfObfuscatedChar": sum(url.count(char) for char in ["@", "%", "\\"]),
        "ObfuscationRatio": sum(url.count(char) for char in ["@", "%", "\\"]) / max(len(url), 1),
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letters / max(len(url), 1),
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digits / max(len(url), 1),
        "NoOfEqualsInURL": url.count("="),
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "NoOfOtherSpecialCharsInURL": special_chars,
        "SpacialCharRatioInURL": special_chars / max(len(url), 1),
        "IsHTTPS": 1 if full_url.startswith("https://") else 0,
        "NoOfURLRedirect": redirects,
        "NoOfSelfRedirect": redirects,
        "NoOfPopup": 1 if "popup" in full_url else 0,
        "NoOfiFrame": 1 if "iframe" in full_url else 0,
        "HasExternalFormSubmit": 1 if any(word in full_url for word in suspicious_words) else 0,
        "HasSubmitButton": 1 if any(word in full_url for word in ["submit", "signin", "login"]) else 0,
        "HasHiddenFields": 1 if "hidden" in full_url else 0,
        "HasPasswordField": 1 if any(word in full_url for word in ["password", "login", "signin"]) else 0,
        "Bank": 1 if "bank" in full_url else 0,
        "Pay": 1 if any(word in full_url for word in ["pay", "paypal", "payment"]) else 0,
        "Crypto": 1 if any(word in full_url for word in ["crypto", "wallet", "bitcoin"]) else 0,
        "HasFavicon": 0,
        "Robots": 0,
        "IsResponsive": 0,
        "HasDescription": 0,
        "HasSocialNet": 0,
        "HasCopyrightInfo": 0,
        "NoOfImage": 0,
        "NoOfCSS": 0,
        "NoOfJS": 0,
        "NoOfSelfRef": 0,
        "NoOfEmptyRef": 1 if not query else 0,
        "NoOfExternalRef": 0,
        "LineOfCode": 0,
        "LargestLineLength": 0,
        "HasTitle": 0,
        "DomainTitleMatchScore": 0,
        "URLTitleMatchScore": 0,
    })
    values.update(fetch_page_features(url))
    return values

def build_model_input_from_values(values):
    row = {feature: values.get(feature, 0) for feature in ml_model.feature_names_in_}
    return pd.DataFrame([row], columns=ml_model.feature_names_in_).astype("float64")

def build_model_input(url):
    if not hasattr(ml_model, "feature_names_in_"):
        return [extract_legacy_features(url)]

    values = extract_feature_values(url)
    return build_model_input_from_values(values)

def get_phishing_label():
    classes = list(ml_model.classes_)
    if -1 in classes:
        return -1
    if 0 in classes and 1 in classes:
        return 0
    return classes[0]

def has_legitimate_page_signals(values):
    positive_signals = [
        values.get("IsHTTPS") == 1,
        values.get("HasTitle") == 1,
        values.get("HasFavicon") == 1,
        values.get("IsResponsive") == 1,
        values.get("HasDescription") == 1,
        values.get("HasCopyrightInfo") == 1,
        values.get("NoOfSelfRef", 0) >= 5,
    ]
    risky_signals = [
        values.get("IsDomainIP") == 1,
        values.get("HasObfuscation") == 1,
        values.get("HasExternalFormSubmit") == 1,
        values.get("NoOfiFrame", 0) > 3,
        values.get("NoOfPopup", 0) > 0,
    ]
    return sum(positive_signals) >= 4 and not any(risky_signals)

def has_strong_phishing_signals(values):
    risky_tld = values.get("TLDLegitimateProb", 1) <= 0.1
    return any([
        values.get("IsDomainIP") == 1,
        values.get("HasObfuscation") == 1,
        values.get("HasExternalFormSubmit") == 1 and values.get("HasPasswordField") == 1,
        risky_tld and values.get("HasPasswordField") == 1,
    ])

def has_clean_url_signals(values):
    return all([
        values.get("IsHTTPS") == 1,
        values.get("IsDomainIP") == 0,
        values.get("HasObfuscation") == 0,
        values.get("TLDLegitimateProb", 0) > 0.1,
        values.get("NoOfSubDomain", 0) <= 2,
        values.get("NoOfPopup", 0) == 0,
    ])

def detect_url(url):
    if ml_model is None:
        raise RuntimeError("Model is not trained yet. Run train_model.py to create model.pkl.")

    url = normalize_url(url)
    domain = get_domain(url)
    safe_browsing_match = check_safe_browsing(url)
    app.logger.info("Safe Browsing result for %s: %s", url, safe_browsing_match)
    if safe_browsing_match is True:
        return "Phishing", 100, url

    if is_official_brand_domain(domain):
        return "Safe", 5, url
    if is_deceptive_brand_domain(domain):
        return "Phishing", 95, url

    values = extract_feature_values(url)
    model_input = build_model_input_from_values(values) if hasattr(ml_model, "feature_names_in_") else [extract_legacy_features(url)]
    prediction = ml_model.predict(model_input)[0]
    probabilities = ml_model.predict_proba(model_input)[0]
    phishing_label = get_phishing_label()
    phishing_index = list(ml_model.classes_).index(phishing_label)
    score = int(probabilities[phishing_index] * 100)
    result = "Phishing" if prediction == phishing_label else "Safe"

    if (
        result == "Phishing"
        and safe_browsing_match is False
        and has_clean_url_signals(values)
        and not has_strong_phishing_signals(values)
    ):
        result = "Safe"
        score = min(score, 25)
    elif result == "Phishing" and score < 85 and has_legitimate_page_signals(values):
        result = "Safe"
        score = min(score, 35)
    elif result == "Safe" and score >= 70 and has_strong_phishing_signals(values):
        result = "Phishing"

    return result, score, url

@app.route('/')
def index():
    if 'loggedin' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = get_cursor(dict_cursor=True)
        if cursor is None:
            flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
            return render_template('login.html')
        cursor.execute('SELECT * FROM users WHERE username=%s OR email=%s ORDER BY id DESC',(username, username))
        accounts = cursor.fetchall()
        account = next((item for item in accounts if password_matches(item['password_hash'], password)), None)
        if account:
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            if is_legacy_hash(account['password_hash']):
                cursor.execute('UPDATE users SET password_hash=%s WHERE id=%s',(hash_password(password), account['id']))
                mysql.connection.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Incorrect username/password!')
    return render_template('login.html')

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = hash_password(request.form['password'])
        cursor = get_cursor()
        if cursor is None:
            flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
            return render_template('register.html')
        cursor.execute('SELECT id FROM users WHERE username=%s OR email=%s',(username,email))
        if cursor.fetchone():
            flash('Username or email already exists.')
            return render_template('register.html')
        try:
            cursor.execute('INSERT INTO users (username,email,password_hash) VALUES (%s,%s,%s)',(username,email,password))
        except MySQLdb.IntegrityError:
            flash('Username or email already exists.')
            return render_template('register.html')
        mysql.connection.commit()
        flash('You have successfully registered!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/forgot', methods=['GET','POST'])
def forgot():
    reset_url = None
    if request.method == 'POST':
        email = request.form['email']
        token = str(uuid.uuid4())
        cursor = get_cursor()
        if cursor is None:
            flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
            return render_template('forgot.html')
        cursor.execute('UPDATE users SET reset_token=%s WHERE email=%s',(token,email))
        mysql.connection.commit()
        if cursor.rowcount:
            reset_url = url_for('reset', token=token)
        else:
            flash('No account found with that email address.')
    return render_template('forgot.html', reset_url=reset_url)

@app.route('/reset/<token>', methods=['GET','POST'])
def reset(token):
    if request.method == 'POST':
        password = hash_password(request.form['password'])
        cursor = get_cursor()
        if cursor is None:
            flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
            return render_template('reset.html')
        cursor.execute('UPDATE users SET password_hash=%s, reset_token=NULL WHERE reset_token=%s',(password,token))
        mysql.connection.commit()
        flash('Password reset successful!')
        return redirect(url_for('login'))
    return render_template('reset.html')

@app.route('/dashboard', methods=['GET','POST'])
def dashboard():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    prediction, score = None, None
    if request.method == 'POST':
        url = request.form['url']
        try:
            prediction, score, normalized_url = detect_url(url)
        except RuntimeError as exc:
            flash(str(exc))
            return redirect(url_for('dashboard'))
        cursor = get_cursor()
        if cursor is None:
            flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
            return redirect(url_for('login'))
        cursor.execute('INSERT INTO history (user_id,url,result,score) VALUES (%s,%s,%s,%s)',(session['id'],normalized_url,prediction,score))
        mysql.connection.commit()
    cursor = get_cursor(dict_cursor=True)
    if cursor is None:
        flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
        return redirect(url_for('login'))
    cursor.execute('SELECT COUNT(*) as total FROM history WHERE user_id=%s',(session['id'],))
    total = cursor.fetchone()['total']
    cursor.execute('SELECT COUNT(*) as phishing FROM history WHERE user_id=%s AND result="Phishing"',(session['id'],))
    phishing = cursor.fetchone()['phishing']
    cursor.execute('SELECT COUNT(*) as safe FROM history WHERE user_id=%s AND result="Safe"',(session['id'],))
    safe = cursor.fetchone()['safe']
    risk_level = "LOW"
    if phishing > safe: risk_level = "HIGH"
    elif phishing == safe: risk_level = "MEDIUM"
    return render_template('dashboard.html', prediction=prediction, score=score, total=total, phishing=phishing, safe=safe, risk_level=risk_level)

@app.route('/history')
def history():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    cursor = get_cursor(dict_cursor=True)
    if cursor is None:
        flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
        return redirect(url_for('login'))
    cursor.execute('SELECT * FROM history WHERE user_id=%s',(session['id'],))
    data = cursor.fetchall()
    return render_template('history.html', history=data)

@app.route('/profile')
def profile():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    cursor = get_cursor(dict_cursor=True)
    if cursor is None:
        flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
        return redirect(url_for('login'))
    cursor.execute('SELECT * FROM users WHERE id=%s',(session['id'],))
    user = cursor.fetchone()
    return render_template('profile.html', user=user)

@app.route('/support', methods=['GET','POST'])
def support():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        issue = request.form['issue']
        cursor = get_cursor()
        if cursor is None:
            flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
            return render_template('support.html', tickets=[], is_main=is_main_user())
        ensure_support_columns(cursor)
        subject = 'Support request'
        cursor.execute(
            '''
            INSERT INTO support_requests (user_id, subject, requester_name, contact_email, message)
            VALUES (%s,%s,%s,%s,%s)
            ''',
            (session['id'], subject, name, email, issue)
        )
        mysql.connection.commit()
        flash('Support ticket submitted!')
    cursor = get_cursor(dict_cursor=True)
    if cursor is None:
        flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
        return render_template('support.html', tickets=[], is_main=is_main_user())
    ensure_support_columns(cursor)
    if is_main_user():
        cursor.execute(
            '''
            SELECT sr.*, u.username, u.email AS account_email
            FROM support_requests sr
            LEFT JOIN users u ON sr.user_id = u.id
            ORDER BY sr.created_at DESC
            '''
        )
    else:
        cursor.execute('SELECT * FROM support_requests WHERE user_id=%s ORDER BY created_at DESC',(session['id'],))
    tickets = format_support_tickets(cursor.fetchall())
    return render_template('support.html', tickets=tickets, is_main=is_main_user())

@app.route('/support/<int:ticket_id>/send', methods=['POST'])
def send_support_reply(ticket_id):
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    if not is_main_user():
        flash('Only the main user can send support replies.')
        return redirect(url_for('support'))
    admin_response = request.form.get('admin_response', '').strip()
    if not admin_response:
        flash('Write a message before sending.')
        return redirect(url_for('support'))
    cursor = get_cursor(dict_cursor=True)
    if cursor is None:
        flash('Database connection failed. Check your MySQL credentials in .env and make sure MySQL is running.')
        return redirect(url_for('support'))
    ensure_support_columns(cursor)
    cursor.execute(
        'UPDATE support_requests SET status=%s, admin_response=%s, resolved_at=NOW() WHERE id=%s',
        ('Resolved', admin_response, ticket_id)
    )
    mysql.connection.commit()
    flash('Reply sent to user.')
    return redirect(url_for('support'))

@app.route('/awareness')
def awareness():
    if 'loggedin' not in session:
        return redirect(url_for('login'))
    return render_template('awareness.html')

if __name__ == '__main__':
    app.run(debug=True)
