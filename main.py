from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import os
import shutil
from datetime import datetime, timedelta
import pytz
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# استخدام متغير بيئة لتأمين مفتاح الجلسات مع قيمة افتراضية آمنة
app.secret_key = os.environ.get('SECRET_KEY', 'strict_enterprise_production_security_key_2026_secure_random')

# تحديد وقت انتهاء الجلسة أمنياً (30 دقيقة من عدم النشاط)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

@app.before_request
def make_session_permanent():
    session.permanent = True

# تحديد المسار المطلق لقاعدة البيانات لتكون ثابتة ومستقلة
basedir = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(basedir, 'database.db')
BACKUP_FOLDER = os.path.join(basedir, 'backups')

UPLOAD_FOLDER = os.path.join(basedir, 'static/uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(BACKUP_FOLDER, exist_ok=True)

# توقيت المملكة العربية السعودية الدقيق
ksa_tz = pytz.timezone('Asia/Riyadh')

def get_ksa_time():
    return datetime.now(ksa_tz).strftime('%Y-%m-%d %H:%M:%S')

def backup_database():
    """نظام النسخ الاحتياطي التلقائي لحماية البيانات من الضياع مع تقييد الصلاحيات"""
    if os.path.exists(DB_PATH):
        timestamp = datetime.now(ksa_tz).strftime('%Y%m%d_%H%M%S')
        backup_filename = os.path.join(BACKUP_FOLDER, f'database_backup_{timestamp}.db')
        try:
            shutil.copy2(DB_PATH, backup_filename)
            # تقييد صلاحيات ملف النسخة الاحتياطية (قراءة لكتاب النظام فقط إن أمكن)
            os.chmod(backup_filename, 0o600)
            print(f"[System Security] تم إنشاء نسخة احتياطية بأمان تام: {backup_filename}")
        except Exception as e:
            print(f"[System Warning] فشل إنشاء النسخة الاحتياطية: {e}")

def init_db():
    backup_database()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL, -- 'employee', 'technician', 'admin'
            company_name TEXT,
            department TEXT
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id INTEGER,
            client_name TEXT NOT NULL,
            company_name TEXT NOT NULL,
            department TEXT NOT NULL,
            category TEXT NOT NULL,
            priority TEXT NOT NULL,
            restarted TEXT NOT NULL,
            issue_description TEXT NOT NULL,
            ai_summary TEXT,
            status TEXT DEFAULT 'New / جديد',
            progress INTEGER DEFAULT 0,
            technician_id INTEGER,
            technician_name TEXT,
            technician_notes TEXT,
            client_rejection_notes TEXT,
            attachment TEXT,
            created_at TEXT,
            FOREIGN KEY(employee_id) REFERENCES users(id),
            FOREIGN KEY(technician_id) REFERENCES users(id)
        )
    ''')
    
    cursor.execute("PRAGMA table_info(tickets)")
    existing_columns = [col[1] for col in cursor.fetchall()]
    columns_to_check = [
        ('client_rejection_notes', 'TEXT'),
        ('technician_notes', 'TEXT'),
        ('technician_id', 'INTEGER'),
        ('technician_name', 'TEXT'),
        ('ai_summary', 'TEXT'),
        ('attachment', 'TEXT')
    ]
    for col_name, col_type in columns_to_check:
        if col_name not in existing_columns:
            cursor.execute(f"ALTER TABLE tickets ADD COLUMN {col_name} {col_type}")
    
    # حسابات أساسية للاختبار مع تشفير كلمات المرور (Password Hashing)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_users = [
            ('admin', generate_password_hash('Admin@2026'), 'مدير النظام الرئيسي', 'admin', 'الإدارة العليا', 'الإدارة'),
            ('tech_kamal', generate_password_hash('Tech@2026'), 'كمال (فني أول)', 'technician', 'الإدارة الهندسية', 'الدعم الفني'),
            ('employee_jawad', generate_password_hash('Jawad@2026'), 'جواد بن محفوظ', 'employee', 'شركة لدن', 'التقنية')
        ]
        cursor.executemany("INSERT INTO users (username, password, full_name, role, company_name, department) VALUES (?, ?, ?, ?, ?, ?)", default_users)
        conn.commit()
        
    conn.close()

def analyze_issue_with_ai(category, description):
    desc = description.lower()
    cat = category.lower()
    
    if "microsoft" in cat or "365" in cat or "outlook" in desc or "email" in desc or "البريد" in desc:
        return "AI Insight: Potential M365 authentication token expiration or cached credentials mismatch. Recommended: Clear local credential manager and re-login."
    elif "erp" in cat or "odoo" in cat or "database" in desc:
        return "AI Insight: ERP database transaction lock or active session timeout detected. Recommended: Terminate hanging worker sessions and refresh cache."
    elif "network" in cat or "شبكة" in cat or "vpn" in desc or "router" in desc:
        return "AI Insight: Network gateway latency or physical link degradation identified. Recommended: Inspect switch port status and verify routing table."
    elif "camera" in cat or "حماية" in cat or "كاميرات" in desc:
        return "AI Insight: Surveillance stream timeout or NVR snapshot backlog. Recommended: Verify SADP tool reachability and stream codecs."
    else:
        return "AI Insight: Local system runtime anomaly detected. Recommended: Clear temp files and perform clean service restart."

@app.route('/set_language/<lang>')
def set_language(lang):
    if lang in ['ar', 'en']:
        session['lang'] = lang
    return redirect(request.referrer or url_for('index'))

@app.route('/')
def index():
    if not session.get('user_id'):
        return redirect(url_for('global_login'))
    if session.get('role') in ['technician', 'admin']:
        return redirect(url_for('agent_dashboard'))
    else:
        return redirect(url_for('employee_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def global_login():
    error = None
    if request.method == 'POST':
        raw_username = request.form['username']
        password = request.form['password']
        
        username = raw_username.strip().lower()
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE LOWER(username) = ?", (username,))
        user = cursor.fetchone()
        
        authenticated = False
        # التحقق الآمن باستخدام check_password_hash ودعم التوافق مع الكلمات القديمة
        if user:
            stored_password = user['password']
            if stored_password and (check_password_hash(stored_password, password) or stored_password == password):
                authenticated = True

        conn.close()
        
        if authenticated and user:
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name']
            session['role'] = user['role']
            session['company_name'] = user['company_name']
            session['department'] = user['department']
            
            if user['role'] in ['technician', 'admin']:
                return redirect(url_for('agent_dashboard'))
            else:
                return redirect(url_for('employee_dashboard'))
        else:
            error = 'اسم المستخدم أو كلمة المرور غير صحيحة.' if session.get('lang', 'ar') == 'ar' else 'Invalid username or password.'
            
    return render_template('global_login.html', error=error)

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    success = None
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        raw_password = request.form['password']
        password = generate_password_hash(raw_password) # تشفير كلمة المرور عند التسجيل
        full_name = request.form['full_name']
        company_name = request.form['company_name']
        department = request.form['department']
        role = 'employee'
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute("SELECT id FROM users WHERE LOWER(username) = ?", (username,))
            if cursor.fetchone():
                raise sqlite3.IntegrityError("User already exists")

            cursor.execute('''
                INSERT INTO users (username, password, full_name, role, company_name, department)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (username, password, full_name, role, company_name, department))
            conn.commit()
            success = 'تم تسجيل حساب الموظف بنجاح! يمكنك تسجيل الدخول.'
        except sqlite3.IntegrityError:
            error = 'اسم المستخدم موجود مسبقاً.'
        finally:
            conn.close()
            
    return render_template('register.html', error=error, success=success)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('global_login'))

@app.route('/employee')
def employee_dashboard():
    if not session.get('user_id') or session.get('role') != 'employee':
        return redirect(url_for('global_login'))
        
    user_id = session['user_id']
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM tickets WHERE employee_id = ? ORDER BY id DESC", (user_id,))
    my_tickets = cursor.fetchall()
    
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE employee_id = ?", (user_id,))
    total_my_tickets = cursor.fetchone()[0]
    
    conn.close()
    
    return render_template('employee_dashboard.html', my_tickets=my_tickets, total_my_tickets=total_my_tickets)

@app.route('/add_ticket', methods=['POST'])
def add_ticket():
    if not session.get('user_id') or session.get('role') != 'employee':
        return redirect(url_for('global_login'))
        
    employee_id = session['user_id']
    client_name = request.form.get('client_name', session['full_name'])
    company_name = request.form.get('company_name', session['company_name'])
    department = request.form.get('department', session['department'])
    category = request.form['category']
    priority = request.form['priority']
    restarted = request.form['restarted']
    issue_description = request.form['issue_description']
    created_at = get_ksa_time()
    
    filename = None
    if 'attachment' in request.files:
        file = request.files['attachment']
        if file and file.filename != '':
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
    ai_summary = analyze_issue_with_ai(category, issue_description)
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO tickets (employee_id, client_name, company_name, department, category, priority, restarted, issue_description, ai_summary, attachment, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', (employee_id, client_name, company_name, department, category, priority, restarted, issue_description, ai_summary, filename, created_at))
    conn.commit()
    conn.close()
    
    return redirect(url_for('employee_dashboard') + '?success=true')

@app.route('/reject_solution/<int:ticket_id>', methods=['POST'])
def reject_solution(ticket_id):
    if not session.get('user_id') or session.get('role') != 'employee':
        return redirect(url_for('global_login'))
        
    rejection_notes = request.form['client_rejection_notes']
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE tickets 
        SET status = 'Reopened / معادة للفتح', progress = 30, client_rejection_notes = ?
        WHERE id = ? AND employee_id = ?
    ''', (rejection_notes, ticket_id, session['user_id']))
    conn.commit()
    conn.close()
    
    return redirect(url_for('employee_dashboard'))

@app.route('/add_ticket_message/<int:ticket_id>', methods=['POST'])
def add_ticket_message(ticket_id):
    if 'user_id' not in session:
        return redirect(url_for('global_login'))
    
    message_text = request.form.get('message_text')
    action_type = request.form.get('action_type')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    if action_type == 'reopen':
        cursor.execute('''
            UPDATE tickets 
            SET status = 'قيد المعالجة (مفتوحة مجدداً)', 
                technician_notes = COALESCE(technician_notes, '') || ? 
            WHERE id = ?
        ''', (f"\n[ملاحظة الموظف]: {message_text}", ticket_id))
    else:
        cursor.execute('''
            UPDATE tickets 
            SET technician_notes = COALESCE(technician_notes, '') || ? 
            WHERE id = ?
        ''', (f"\n[تعليق الموظف]: {message_text}", ticket_id))
        
    conn.commit()
    conn.close()
    
    if session.get('role') in ['technician', 'admin']:
        return redirect(url_for('agent_dashboard'))
    else:
        return redirect(url_for('employee_dashboard'))

@app.route('/agent')
def agent_dashboard():
    if not session.get('user_id') or session.get('role') not in ['technician', 'admin']:
        return redirect(url_for('global_login'))
        
    search_query = request.args.get('search', '')
    status_filter = request.args.get('status', 'All')
    from_date = request.args.get('from_date', '')
    to_date = request.args.get('to_date', '')
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = "SELECT * FROM tickets WHERE 1=1"
    params = []
    
    if search_query:
        query += " AND (client_name LIKE ? OR company_name LIKE ? OR department LIKE ?)"
        params.extend([f'%{search_query}%', f'%{search_query}%', f'%{search_query}%'])
        
    if status_filter == 'Active':
        query += " AND status != 'Closed / مغلق نهائياً'"
    elif status_filter == 'Closed':
        query += " AND status = 'Closed / مغلق نهائياً'"
        
    if from_date:
        query += " AND date(created_at) >= ?"
        params.append(from_date)
    if to_date:
        query += " AND date(created_at) <= ?"
        params.append(to_date)
        
    query += " ORDER BY id DESC"
    
    cursor.execute(query, params)
    tickets = cursor.fetchall()
    
    cursor.execute('SELECT COUNT(*) FROM tickets')
    total_tickets = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE status != 'Closed / مغلق نهائياً'")
    open_tickets = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tickets WHERE status = 'Closed / مغلق نهائياً'")
    closed_tickets = cursor.fetchone()[0]
    
    conn.close()
    
    return render_template('agent_dashboard.html', 
                           tickets=tickets, 
                           total_tickets=total_tickets, 
                           open_tickets=open_tickets, 
                           closed_tickets=closed_tickets,
                           current_search=search_query,
                           current_status=status_filter,
                           from_date=from_date,
                           to_date=to_date)

@app.route('/update_ticket/<int:ticket_id>', methods=['POST'])
def update_ticket(ticket_id):
    if not session.get('user_id') or session.get('role') not in ['technician', 'admin']:
        return redirect(url_for('global_login'))
        
    status = request.form['status5'] if 'status5' in request.form else request.form.get('status', 'New / جديد')
    progress = request.form['progress']
    technician_notes = request.form.get('technician_notes', '')
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT technician_id, technician_name FROM tickets WHERE id = ?", (ticket_id,))
    ticket_data = cursor.fetchone()
    
    current_tech_id = ticket_data['technician_id']
    current_tech_name = ticket_data['technician_name']
    
    if not current_tech_id or current_tech_id == session['user_id'] or session['role'] == 'admin':
        tech_id_to_save = current_tech_id if current_tech_id else session['user_id']
        tech_name_to_save = current_tech_name if current_tech_name else session['full_name']
        
        cursor.execute('''
            UPDATE tickets 
            SET status = ?, progress = ?, technician_id = ?, technician_name = ?, technician_notes = ?
            WHERE id = ?
        ''', (status, progress, tech_id_to_save, tech_name_to_save, technician_notes, ticket_id))
        conn.commit()
        
    conn.close()
    return redirect(url_for('agent_dashboard'))

@app.route('/admin/users')
def admin_users():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('global_login'))
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users ORDER BY id DESC")
    users = cursor.fetchall()
    conn.close()
    
    return render_template('admin_users.html', users=users)

@app.route('/admin/add_user', methods=['POST'])
def admin_add_user():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('global_login'))
        
    username = request.form['username'].strip().lower()
    raw_password = request.form['password']
    password = generate_password_hash(raw_password)
    full_name = request.form['full_name']
    role = request.form['role']
    company_name = request.form.get('company_name', 'لدن العربية')
    department = request.form.get('department', 'عام')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE LOWER(username) = ?", (username,))
        if cursor.fetchone():
            raise sqlite3.IntegrityError("User already exists")

        cursor.execute('''
            INSERT INTO users (username, password, full_name, role, company_name, department)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, password, full_name, role, company_name, department))
        conn.commit()
    except sqlite3.IntegrityError:
        pass 
    finally:
        conn.close()
        
    return redirect(url_for('admin_users'))

@app.route('/admin/update_user_role/<int:user_id>', methods=['POST'])
def admin_update_user_role(user_id):
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('global_login'))
        
    new_role = request.form['role']
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/update_password/<int:user_id>', methods=['POST'])
def admin_update_password(user_id):
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('global_login'))
        
    new_raw_password = request.form['new_password']
    new_password = generate_password_hash(new_raw_password)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET password = ? WHERE id = ?", (new_password, user_id))
    conn.commit()
    conn.close()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('global_login'))
        
    if user_id != session['user_id']:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
    return redirect(url_for('admin_users'))

@app.route('/admin/backup', methods=['POST'])
def admin_backup_database():
    if not session.get('user_id') or session.get('role') != 'admin':
        return redirect(url_for('global_login'))
    
    backup_database()
    return redirect(url_for('agent_dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', debug=False, port=5000)