from flask import Flask, request, jsonify, send_from_directory, abort, render_template
import os
import requests
import base64
from werkzeug.utils import secure_filename
import logging
from functools import wraps
from dotenv import load_dotenv
import socket
import ssl
from flask import flash, redirect, url_for, session
from osint_utils.models import db, User
import secrets
from datetime import datetime, timedelta
from flask import render_template, request
import smtplib
from email.mime.text import MIMEText
from flask import Flask, render_template, request, redirect, url_for, session, flash



load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///sherlockibp.db'
db.init_app(app)
app.secret_key = os.getenv("SECRET_KEY", "super-secret-key")
app.secret_key = "supersecretkey"  

print("EMAIL_SENDER:", os.getenv("EMAIL_SENDER"))
print(" EMAIL_PASSWORD:", os.getenv("EMAIL_PASSWORD"))
print(" SMTP_SERVER:", os.getenv("SMTP_SERVER"))
print(" SMTP_PORT:", os.getenv("SMTP_PORT"))
print("Flask static folder:", app.static_folder)
UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

API_KEY = os.getenv("API_KEY")
IMGBB_API_KEY = os.getenv("IMGBB_API_KEY")
HIBP_API_KEY = os.getenv("HIBP_API_KEY")

print(" Loaded API Key:", API_KEY)


if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        client_key = request.headers.get("x-api-key")
        if client_key and client_key == API_KEY:
            return f(*args, **kwargs)
        abort(403)
    return decorated_function

def check_username_exists(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def check_email_breach(email):
    headers = {
        'hibp-api-key': HIBP_API_KEY,
        'user-agent': 'YourOSINTTool'
    }
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=true"
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return True
        elif response.status_code == 404:
            return False
    except requests.RequestException as e:
        app.logger.error(f"HIBP check failed for {email}: {e}")
    return None


#@app.before_request
#def block_untrusted_hosts():
 #   allowed_hosts = ["127.0.0.1", "localhost"]
  #  host = request.host.split(':')[0]
   # if host not in allowed_hosts:
    #    abort(403)

def upload_to_imgbb(image_path, api_key):
    with open(image_path, "rb") as file:
        encoded_string = base64.b64encode(file.read()).decode('utf-8')
    url = "https://api.imgbb.com/1/upload"
    payload = {'key': api_key, 'image': encoded_string}
    response = requests.post(url, data=payload)
    if response.status_code == 200:
        return response.json()['data']['url']
    else:
        app.logger.error(f"ImgBB upload failed: {response.text}")
        return None

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_image():
    if 'image' not in request.files:
        return jsonify({'error': 'No image uploaded'}), 400
    file = request.files['image']
    if file.filename == '':
        return jsonify({'error': 'Empty filename'}), 400
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    public_url = upload_to_imgbb(filepath, IMGBB_API_KEY)
    if not public_url:
        return jsonify({'error': 'Failed to upload image to ImgBB'}), 500

    reverse_links = {
        'yandex': f'https://yandex.com/images/search?rpt=imageview&url={public_url}',
        'google': f'https://lens.google.com/uploadbyurl?url={public_url}',
        'bing': f'https://www.bing.com/images/search?view=detailv2&iss=sbi&imgurl={public_url}',
        'tineye': f'https://tineye.com/search?url={public_url}'
    }

    return jsonify({
        'message': 'Image uploaded and hosted successfully',
        'imgbb_url': public_url,
        'reverse_search_links': reverse_links
    })

@app.route('/lookup/ip', methods=['POST'])
@require_api_key
def lookup_ip():
    data = request.json
    ip = data.get('ip', '').strip()
    if not ip:
        return jsonify({'error': 'No IP address provided'}), 400

    try:
        response = requests.get(f'https://ipapi.co/{ip}/json/')
        response.raise_for_status()
        return jsonify({'ip_data': response.json()})
    except requests.RequestException as e:
        app.logger.error(f"IP lookup failed for {ip}: {e}")
        return jsonify({'error': 'Failed to retrieve IP information'}), 500



@app.route('/full-osint', methods=['GET'])
def full_osint_form():
    return render_template('full_osint_form.html')

@app.route('/full-osint', methods=['POST'])
def handle_full_osint():
    name = request.form.get('name', '').strip()
    dob = request.form.get('dob', '').strip()
    image = request.files.get('image')

    if not name or not dob or not image:
        return jsonify({'error': 'Missing name, DOB, or image'}), 400

    parts = name.lower().split()
    first = parts[0] if len(parts) > 0 else ''
    last = parts[1] if len(parts) > 1 else ''

    username_variants = list(set([
        first + last,
        last + first,
        f"{first}.{last}",
        f"{last}.{first}",
        f"{first[0]}{last}",
        f"{first}{last[0]}",
        f"{first}_{last}",
        f"{first}{dob[-2:]}",
        f"{first}{dob[:4]}",
        f"{first}{dob.replace('-', '')}",
    ]))

    platforms = {
        "vk": "https://vk.com/{}",
        "telegram": "https://t.me/{}",
        "github": "https://github.com/{}",
        "ok": "https://ok.ru/profile/{}",
        "dzen": "https://dzen.ru/profile/{}"
    }

    username_search_results = {}
    for platform, url_pattern in platforms.items():
        username_search_results[platform] = []
        for username in username_variants:
            profile_url = url_pattern.format(username)
            exists = check_username_exists(profile_url)
            username_search_results[platform].append({
                'username': username,
                'url': profile_url,
                'exists': exists
            })

    email_domains = ['gmail.com', 'yandex.ru', 'mail.ru', 'rambler.ru', 'outlook.com']
    email_guesses = []
    for username in username_variants:
        for domain in email_domains:
            email = f"{username}@{domain}"
            try:
                headers = {
                    'hibp-api-key': HIBP_API_KEY,
                    'user-agent': 'YourOSINTTool'
                }
                hibp_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=true"
                response = requests.get(hibp_url, headers=headers)
                if response.status_code == 200:
                    breached = True
                elif response.status_code == 404:
                    breached = False
                else:
                    breached = None
            except Exception as e:
                app.logger.error(f"HIBP check failed for {email}: {e}")
                breached = None

            email_guesses.append({
                'email': email,
                'breached': breached
            })

    filename = secure_filename(image.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    image.save(filepath)

    public_url = upload_to_imgbb(filepath, IMGBB_API_KEY)
    if not public_url:
        return jsonify({'error': 'Failed to upload image to ImgBB'}), 500

    reverse_links = {
        'yandex': f'https://yandex.com/images/search?rpt=imageview&url={public_url}',
        'google': f'https://lens.google.com/uploadbyurl?url={public_url}',
        'bing': f'https://www.bing.com/images/search?view=detailv2&iss=sbi&imgurl={public_url}',
        'tineye': f'https://tineye.com/search?url={public_url}'
    }

    return jsonify({
        'name': name,
        'dob': dob,
        'imgbb_url': public_url,
        'reverse_search_links': reverse_links,
        'username_search_links': username_search_results,
        'email_guesses': email_guesses
    })

@app.route('/lookup/domain', methods=['POST'])
@require_api_key
def lookup_domain():
    data = request.json
    domain = data.get('domain', '').strip()
    if not domain:
        return jsonify({'error': 'No domain provided'}), 400

    try:
        search_urls = [
            f"https://www.similarweb.com/website/{domain}/",
            f"https://builtwith.com/{domain}",
            f"https://who.is/whois/{domain}",
            f"https://crt.sh/?q={domain}",
            f"https://securitytrails.com/domain/{domain}"
        ]
        return jsonify({'domain': domain, 'search_urls': search_urls})
    except Exception as e:
        app.logger.error(f"Domain lookup error: {e}")
        return jsonify({'error': 'Failed to perform domain lookup'}), 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()

        # Check for existing user
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing_user:
            flash("⚠️ Username or email already exists. Please use different credentials.")
            return redirect(url_for("register"))

        agent_id = secrets.token_hex(8)
        subscription_expires = datetime.utcnow() + timedelta(days=31)

        user = User(
            username=username,
            email=email,
            agent_id=agent_id,
            password_hash="placeholder",
            subscription_expires=subscription_expires
        )
        db.session.add(user)
        db.session.commit()

        return f"Registered successfully! Welcome, Agent {username}."

    return render_template('register.html')


@app.route('/get-agent-id', methods=['GET', 'POST'])
def get_agent_id():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        user = User.query.filter_by(username=username).first()

        if not user:
            flash("Username not found. Please enter a valid registered username.")
            return redirect(url_for("get_agent_id"))


        # Generate a unique Agent ID
        new_agent_id = secrets.token_hex(8)
        user.agent_id = new_agent_id
        user.subscription_expires = datetime.utcnow() + timedelta(days=31)

        db.session.commit()

        # Send Agent ID to email
        subject = "Your SherlockIBP Agent ID"
        body = f"Hello Agent {username},\n\nHere is your Agent ID:\n\n{new_agent_id}\n\nThis will be valid for 31 days."
        send_email(user.email, subject, body)

        return f" Agent ID sent to {user.email}"

    return render_template('get_agent_id.html')


def send_email(to, subject, body):
    try:
        sender = os.getenv("EMAIL_SENDER")
        password = os.getenv("EMAIL_PASSWORD")
        smtp_server = os.getenv("SMTP_SERVER")
        smtp_port = int(os.getenv("SMTP_PORT"))

        print(f" Sending email FROM: {sender}")
        print(f" Sending email TO: {to}")
        print(f" Body:\n{body}")

        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = to

        with smtplib.SMTP_SSL(smtp_server, smtp_port) as server:
            server.login(sender, password)
            server.send_message(msg)

        print(" Email function completed.")
    except Exception as e:
        print(f" Failed to send email to {to}: {e}")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        agent_id = request.form.get("agent_id", "").strip()
        user = User.query.filter_by(username=username, agent_id=agent_id).first()

        if user:
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        else:
            flash(" Invalid Agent ID or username. Try again.")
            return redirect(url_for("login"))

    return render_template("login.html")



@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if not session.get("logged_in"):
        flash("Access denied. Please log in.")
        return redirect(url_for("login"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        dob = request.form.get("dob", "").strip()
        image = request.files.get("image")

        filled_fields = [bool(name), bool(dob), bool(image)]
        if filled_fields.count(True) < 2:
            flash("Please provide at least 2 of the 3: name, date of birth, or image.")
            return redirect(url_for("dashboard"))

        session["osint_results"] = {
            "name": name,
            "dob": dob,
            "image_uploaded": bool(image)
        }

        return redirect(url_for("results"))

    return render_template("dashboard.html", results_shown=False)


@app.route("/search", methods=["POST"])
def search():
    name = request.form.get("name", "").strip()
    dob = request.form.get("dob", "").strip()
    image = request.files.get("image")

    # Count how many fields are filled
    filled_fields = sum(bool(x) for x in [name, dob, image and image.filename])
    if filled_fields < 2:
        flash("Please provide at least two of the three fields.")
        return redirect(url_for("dashboard"))

   
    return render_template("dashboard.html", results_shown=True)

@app.route("/results")
def results():
    if not session.get("logged_in"):
        flash("Access denied. Please log in.")
        return redirect(url_for("login"))

    results = session.get("osint_results", {})
    if not results:
        flash("No search data found.")
        return redirect(url_for("dashboard"))

    # Simulated result bubbles (replace with real tool outputs later)
    orb_data = {
        "social": "Social Found",
        "image": "Image Match",
        "breach": "Email Breach",
        "domain": "Domain Intel",
        "summary": "AI Summary"
    }

    return render_template("results.html", results=orb_data)


if __name__ == '__main__':
    app.secret_key = os.getenv("SECRET_KEY", "super-secret-key")
    with app.app_context():
        from osint_utils.models import db
        db.create_all()

    app.run(debug=True)
