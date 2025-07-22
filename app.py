from flask import Flask, request, jsonify, render_template, session, redirect, url_for, flash, send_file, abort
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
from datetime import datetime
import uuid
from functools import wraps
import requests  # For Telegram integration

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your-secret-key-change-this-in-production')

# Data file paths
DATA_DIR = 'data'
USERS_FILE = os.path.join(DATA_DIR, 'users.json')
CHALLENGES_FILE = os.path.join(DATA_DIR, 'challenges.json')
SCORES_FILE = os.path.join(DATA_DIR, 'scores.json')
SUBMISSIONS_FILE = os.path.join(DATA_DIR, 'submissions.json')
ANNOUNCEMENTS_FILE = os.path.join(DATA_DIR, 'announcements.json')
CONFIG_FILE = os.path.join(DATA_DIR, 'config.json')
LOGINS_FILE = os.path.join(DATA_DIR, 'logins.json')
TEAMS_FILE = os.path.join(DATA_DIR, 'teams.json')

def load_json(filename):
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

def get_config():
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except:
        default_config = {
            "ctf_active": False,
            "ctf_start": "",
            "ctf_end": "",
            "dynamic_scoring": True,
            "team_mode": False,
            "rate_limit": 5,
            "min_score": 25,
            "telegram_bot_token": "",
            "telegram_chat_id": ""
        }
        save_json(CONFIG_FILE, default_config)
        return default_config

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        users = load_json(USERS_FILE)
        user = next((u for u in users if u['id'] == session['user_id']), None)
        if not user or not user.get('is_admin', False):
            flash('Admin access required!', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def log_submission(user_id, challenge_id, flag, success, ip):
    submissions = load_json(SUBMISSIONS_FILE)
    submission = {
        "timestamp": datetime.now().isoformat(),
        "user_id": user_id,
        "challenge_id": challenge_id,
        "flag": flag,
        "success": success,
        "ip": ip
    }
    submissions.append(submission)
    save_json(SUBMISSIONS_FILE, submissions)

def calculate_dynamic_score(base_score, solves, total_users):
    config = get_config()
    if not config.get('dynamic_scoring', True):
        return base_score
    if total_users == 0:
        return base_score
    solve_percentage = solves / total_users
    deduction = int(base_score * 0.4 * solve_percentage)
    final_score = max(config.get('min_score', 25), base_score - deduction)
    return final_score

def generate_avatar_url(user):
    seed = user.get('avatar_seed', user['id'])
    return f"https://api.dicebear.com/7.x/adventurer-neutral/svg?seed={seed}&size=200"

# --- Telegram Bot Integration ---
def send_file_to_telegram(file_path, bot_token, chat_id):
    if not bot_token or not chat_id:
        return
    url = f"https://api.telegram.org/bot{bot_token}/sendDocument"
    with open(file_path, 'rb') as f:
        files = {'document': (os.path.basename(file_path), f)}
        data = {'chat_id': chat_id}
        try:
            requests.post(url, data=data, files=files, timeout=10)
        except Exception as e:
            print(f"Failed to send {file_path} to Telegram: {e}")

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        team_name = request.form.get('team_name', '').strip()
        users = load_json(USERS_FILE)
        if any(u['username'] == username or u['email'] == email for u in users):
            flash('Username or email already exists!', 'error')
            return render_template('register.html')
        user = {
            "id": str(uuid.uuid4()),
            "username": username,
            "email": email,
            "password": generate_password_hash(password),
            "is_admin": len(users) == 0,
            "team_name": team_name,
            "created_at": datetime.now().isoformat(),
            "avatar_seed": str(uuid.uuid4()),
            "bio": "",
            "location": "",
            "website": ""
        }
        users.append(user)
        save_json(USERS_FILE, users)
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    config = get_config()
    return render_template('register.html', team_mode=config.get('team_mode', False))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        users = load_json(USERS_FILE)
        user = next((u for u in users if u['username'] == username), None)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user.get('is_admin', False)
            logins = load_json(LOGINS_FILE)
            login_entry = {
                "timestamp": datetime.now().isoformat(),
                "user_id": user['id'],
                "username": username,
                "ip": request.remote_addr
            }
            logins.append(login_entry)
            save_json(LOGINS_FILE, logins)
            if user.get('is_admin', False):
                return redirect(url_for('admin_panel'))
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials!', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    config = get_config()
    if not config.get('ctf_active', False):
        all_announcements = load_json(ANNOUNCEMENTS_FILE)
        latest_announcement = all_announcements[-1] if all_announcements else None
        return render_template('dashboard.html', 
                             ctf_active=False, 
                             challenges=[], 
                             latest_announcement=latest_announcement,
                             all_announcements=all_announcements,
                             user_rank=None,
                             user_total_score=0,
                             user_solved_count=0,
                             total_challenges=0,
                             recent_solves=[])
    challenges = load_json(CHALLENGES_FILE)
    visible_challenges = [c for c in challenges if c.get('visible', True)]
    scores = load_json(SCORES_FILE)
    user_scores = [s for s in scores if s['user_id'] == session['user_id']]
    solved_challenges = [s['challenge_id'] for s in user_scores]
    user_total_score = sum(s['score'] for s in user_scores)
    user_solved_count = len(set(solved_challenges))
    total_challenges = len(visible_challenges)
    users = load_json(USERS_FILE)
    all_user_scores = {}
    for score in scores:
        user_id = score['user_id']
        if user_id not in all_user_scores:
            all_user_scores[user_id] = 0
        all_user_scores[user_id] += score['score']
    sorted_scores = sorted(all_user_scores.items(), key=lambda x: x[1], reverse=True)
    user_rank = None
    for rank, (user_id, score) in enumerate(sorted_scores, 1):
        if user_id == session['user_id']:
            user_rank = rank
            break
    recent_solves = [s for s in user_scores if s.get('challenge_title')]
    recent_solves.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    recent_solves = recent_solves[:5]
    for challenge in visible_challenges:
        challenge['unlocked'] = True
        if challenge.get('requires'):
            challenge['unlocked'] = all(req in solved_challenges for req in challenge['requires'])
        challenge['solved'] = challenge['id'] in solved_challenges
    all_announcements = load_json(ANNOUNCEMENTS_FILE)
    latest_announcement = all_announcements[-1] if all_announcements else None
    return render_template('dashboard.html', 
                         ctf_active=True, 
                         challenges=visible_challenges, 
                         latest_announcement=latest_announcement,
                         all_announcements=all_announcements,
                         user_rank=user_rank,
                         user_total_score=user_total_score,
                         user_solved_count=user_solved_count,
                         total_challenges=total_challenges,
                         recent_solves=recent_solves)

@app.route('/profile')
@app.route('/profile/<username>')
@login_required
def user_profile(username=None):
    users = load_json(USERS_FILE)
    if not username:
        username = session['username']
    user = next((u for u in users if u['username'] == username), None)
    if not user:
        flash('User not found!', 'error')
        return redirect(url_for('dashboard'))
    scores = load_json(SCORES_FILE)
    user_scores = [s for s in scores if s['user_id'] == user['id']]
    total_score = sum(s['score'] for s in user_scores)
    total_solves = len(user_scores)
    all_user_scores = {}
    for score in scores:
        user_id = score['user_id']
        if user_id not in all_user_scores:
            all_user_scores[user_id] = 0
        all_user_scores[user_id] += score['score']
    sorted_scores = sorted(all_user_scores.items(), key=lambda x: x[1], reverse=True)
    user_rank = None
    for rank, (user_id, score) in enumerate(sorted_scores, 1):
        if user_id == user['id']:
            user_rank = rank
            break
    avatar_url = generate_avatar_url(user)
    is_own_profile = session['user_id'] == user['id']
    return render_template('profile.html', 
                         user=user, 
                         avatar_url=avatar_url,
                         total_score=total_score,
                         total_solves=total_solves,
                         user_rank=user_rank or 'Unranked',
                         recent_solves=user_scores[-5:] if user_scores else [],
                         is_own_profile=is_own_profile)

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        users = load_json(USERS_FILE)
        user_index = next(i for i, u in enumerate(users) if u['id'] == session['user_id'])
        users[user_index]['bio'] = request.form.get('bio', '')[:500]
        users[user_index]['location'] = request.form.get('location', '')[:100]
        users[user_index]['website'] = request.form.get('website', '')[:200]
        if 'regenerate_avatar' in request.form:
            users[user_index]['avatar_seed'] = str(uuid.uuid4())
        save_json(USERS_FILE, users)
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('user_profile'))
    users = load_json(USERS_FILE)
    user = next(u for u in users if u['id'] == session['user_id'])
    avatar_url = generate_avatar_url(user)
    return render_template('edit_profile.html', user=user, avatar_url=avatar_url)

@app.route('/submit_flag', methods=['POST'])
@login_required
def submit_flag():
    challenge_id = request.form['challenge_id']
    flag = request.form['flag'].strip()
    config = get_config()
    if not config.get('ctf_active', False):
        return jsonify({"success": False, "message": "CTF is not active!"})
    challenges = load_json(CHALLENGES_FILE)
    challenge = next((c for c in challenges if c['id'] == challenge_id), None)
    if not challenge:
        return jsonify({"success": False, "message": "Challenge not found!"})
    scores = load_json(SCORES_FILE)
    if any(s['user_id'] == session['user_id'] and s['challenge_id'] == challenge_id for s in scores):
        return jsonify({"success": False, "message": "Already solved!"})
    success = flag == challenge['flag']
    log_submission(session['user_id'], challenge_id, flag, success, request.remote_addr)
    if success:
        users = load_json(USERS_FILE)
        total_users = len(users)
        current_solves = len([s for s in scores if s['challenge_id'] == challenge_id])
        final_score = calculate_dynamic_score(
            challenge['base_score'], 
            current_solves, 
            total_users
        )
        score_entry = {
            "user_id": session['user_id'],
            "username": session['username'],
            "challenge_id": challenge_id,
            "challenge_title": challenge['title'],
            "score": final_score,
            "timestamp": datetime.now().isoformat()
        }
        scores.append(score_entry)
        save_json(SCORES_FILE, scores)
        challenge['solves'] = challenge.get('solves', 0) + 1
        save_json(CHALLENGES_FILE, challenges)
        return jsonify({"success": True, "message": f"Correct! +{final_score} points"})
    else:
        return jsonify({"success": False, "message": "Incorrect flag!"})

@app.route('/scoreboard')
def scoreboard():
    scores = load_json(SCORES_FILE)
    users = load_json(USERS_FILE)
    config = get_config()
    user_scores = {}
    for score in scores:
        user_id = score['user_id']
        if user_id not in user_scores:
            user_scores[user_id] = {
                'username': score['username'],
                'total': 0,
                'solves': 0
            }
        user_scores[user_id]['total'] += score['score']
        user_scores[user_id]['solves'] += 1
    leaderboard = sorted(user_scores.values(), key=lambda x: x['total'], reverse=True)
    team_leaderboard = []
    if config.get('team_mode', False):
        team_scores = {}
        for user in users:
            team_name = user.get('team_name', '')
            if team_name and user['id'] in user_scores:
                if team_name not in team_scores:
                    team_scores[team_name] = {'total': 0, 'solves': 0, 'members': []}
                team_scores[team_name]['total'] += user_scores[user['id']]['total']
                team_scores[team_name]['solves'] += user_scores[user['id']]['solves']
                team_scores[team_name]['members'].append(user['username'])
        team_leaderboard = sorted(team_scores.items(), key=lambda x: x[1]['total'], reverse=True)
    return render_template('scoreboard.html', 
                         leaderboard=leaderboard, 
                         team_leaderboard=team_leaderboard,
                         team_mode=config.get('team_mode', False))

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin/panel.html')

@app.route('/admin/config', methods=['GET', 'POST'])
@admin_required
def admin_config():
    if request.method == 'POST':
        config = {
            "ctf_active": 'ctf_active' in request.form,
            "ctf_start": request.form['ctf_start'],
            "ctf_end": request.form['ctf_end'],
            "dynamic_scoring": 'dynamic_scoring' in request.form,
            "team_mode": 'team_mode' in request.form,
            "rate_limit": int(request.form['rate_limit']),
            "min_score": int(request.form['min_score']),
            "telegram_bot_token": request.form['telegram_bot_token'],
            "telegram_chat_id": request.form['telegram_chat_id']
        }
        save_json(CONFIG_FILE, config)
        flash('Configuration updated!', 'success')
    config = get_config()
    return render_template('admin/config.html', config=config)

@app.route('/admin/challenges', methods=['GET', 'POST'])
@admin_required
def admin_challenges():
    if request.method == 'POST':
        action = request.form['action']
        if action == 'add':
            challenges = load_json(CHALLENGES_FILE)
            challenge = {
                "id": request.form['id'],
                "title": request.form['title'],
                "description": request.form['description'],
                "category": request.form['category'],
                "flag": request.form['flag'],
                "base_score": int(request.form['base_score']),
                "difficulty": request.form['difficulty'],
                "visible": 'visible' in request.form,
                "solves": 0,
                "requires": request.form['requires'].split(',') if request.form['requires'] else [],
                "hints": []
            }
            challenges.append(challenge)
            save_json(CHALLENGES_FILE, challenges)
            flash('Challenge added!', 'success')
        elif action == 'delete':
            challenges = load_json(CHALLENGES_FILE)
            challenge_id = request.form['challenge_id']
            challenges = [c for c in challenges if c['id'] != challenge_id]
            save_json(CHALLENGES_FILE, challenges)
            flash('Challenge deleted!', 'success')
    challenges = load_json(CHALLENGES_FILE)
    return render_template('admin/challenges.html', challenges=challenges)

@app.route('/admin/users')
@admin_required
def admin_users():
    users = load_json(USERS_FILE)
    logins = load_json(LOGINS_FILE)
    return render_template('admin/users.html', users=users, logins=logins)

# --- Promote User to Admin ---
@app.route('/admin/promote/<user_id>', methods=['POST'])
@admin_required
def promote_user(user_id):
    users = load_json(USERS_FILE)
    user = next((u for u in users if u['id'] == user_id), None)
    if not user:
        flash('User not found!', 'error')
    else:
        user['is_admin'] = True
        save_json(USERS_FILE, users)
        flash(f"User {user['username']} promoted to admin!", 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/announcements', methods=['GET', 'POST'])
@admin_required
def admin_announcements():
    if request.method == 'POST':
        announcements = load_json(ANNOUNCEMENTS_FILE)
        announcement = {
            "id": str(uuid.uuid4()),
            "title": request.form['title'],
            "content": request.form['content'],
            "timestamp": datetime.now().isoformat()
        }
        announcements.append(announcement)
        save_json(ANNOUNCEMENTS_FILE, announcements)
        flash('Announcement added!', 'success')
    announcements = load_json(ANNOUNCEMENTS_FILE)
    return render_template('admin/announcements.html', announcements=announcements)

@app.route('/admin/announcements/delete/<announcement_id>', methods=['POST'])
@admin_required
def delete_announcement(announcement_id):
    try:
        announcements = load_json(ANNOUNCEMENTS_FILE)
        updated_announcements = [a for a in announcements if a.get('id') != announcement_id]
        if len(updated_announcements) == len(announcements):
            return jsonify({"success": False, "message": "Announcement not found!"})
        save_json(ANNOUNCEMENTS_FILE, updated_announcements)
        return jsonify({"success": True, "message": "Announcement deleted successfully!"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error deleting announcement: {str(e)}"})

@app.route('/admin/submissions')
@admin_required
def admin_submissions():
    submissions = load_json(SUBMISSIONS_FILE)
    return render_template('admin/submissions.html', submissions=submissions)

@app.route('/admin/reset', methods=['GET', 'POST'])
@admin_required
def admin_reset():
    if request.method == 'POST':
        # Send all JSON files to Telegram before reset
        config = get_config()
        bot_token = config.get('telegram_bot_token')
        chat_id = config.get('telegram_chat_id')
        json_files = [
            USERS_FILE, CHALLENGES_FILE, SCORES_FILE, SUBMISSIONS_FILE,
            ANNOUNCEMENTS_FILE, CONFIG_FILE, LOGINS_FILE, TEAMS_FILE
        ]
        for file_path in json_files:
            if os.path.exists(file_path):
                send_file_to_telegram(file_path, bot_token, chat_id)
        # Now reset as before
        save_json(SCORES_FILE, [])
        save_json(SUBMISSIONS_FILE, [])
        save_json(LOGINS_FILE, [])
        users = load_json(USERS_FILE)
        admin_users = [u for u in users if u.get('is_admin', False)]
        save_json(USERS_FILE, admin_users)
        # Reset solves count for all challenges
        challenges = load_json(CHALLENGES_FILE)
        for challenge in challenges:
            challenge['solves'] = 0
        save_json(CHALLENGES_FILE, challenges)
        flash('CTF Reset Complete!', 'success')
    return render_template('admin/reset.html')

# ----------- ADMIN DOWNLOAD ROUTE -----------
@app.route('/admin/download/<filename>')
@admin_required
def admin_download_file(filename):
    allowed_files = [
        'users.json', 'challenges.json', 'scores.json', 'submissions.json',
        'announcements.json', 'config.json', 'logins.json', 'teams.json'
    ]
    if filename not in allowed_files:
        abort(404)
    file_path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(file_path):
        abort(404)
    return send_file(file_path, as_attachment=True)
# --------------------------------------------

if __name__ == '__main__':
    os.makedirs(DATA_DIR, exist_ok=True)
    for file_path in [USERS_FILE, CHALLENGES_FILE, SCORES_FILE, SUBMISSIONS_FILE, ANNOUNCEMENTS_FILE, LOGINS_FILE, TEAMS_FILE]:
        if not os.path.exists(file_path):
            save_json(file_path, [])
    if not os.path.exists(CONFIG_FILE):
        get_config()
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug, host='0.0.0.0', port=port)
