import sqlite3
import socket
import io
from flask import send_file
from flask import Flask, request, redirect, url_for, session, render_template
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'your_very_secret_key' 

# Database File Name
DB_NAME = 'class_portal.db'

def get_local_ip():
    try:
        # Connect to a public DNS to find the correct outgoing IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_db_connection():
    try:
        conn = sqlite3.connect(DB_NAME)
        # This allows accessing columns by name (like a dictionary)
        conn.row_factory = sqlite3.Row 
        return conn
    except sqlite3.Error as err:
        print(f"Error connecting to SQLite: {err}")
        return None

# --- DATABASE INITIALIZATION (Run once on startup) ---
def init_db():
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        # Create Users Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        # Create Enrollments Table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS enrollments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                teacher_id TEXT,
                student_id TEXT,
                grade TEXT DEFAULT 'N/A',
                attendance TEXT DEFAULT 'Present',
                assignments_due INTEGER DEFAULT 0,
                FOREIGN KEY(teacher_id) REFERENCES users(user_id),
                FOREIGN KEY(student_id) REFERENCES users(user_id)
            )
        ''')
        conn.commit()
        conn.close()
        print("Database initialized successfully.")

# --- REGISTER ROUTE ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    message = ''
    if request.method == 'POST':
        name = request.form.get('name')
        user_id = request.form.get('student_id') 
        password = request.form.get('password')
        role = request.form.get('role')

        if not (name and user_id and password and role):
            message = "All fields are required!"
        else:
            conn = get_db_connection()
            if conn:
                cursor = conn.cursor()
                try:
                    # Check if ID already exists
                    check_query = "SELECT * FROM users WHERE user_id = ?"
                    cursor.execute(check_query, (user_id,))
                    if cursor.fetchone():
                        message = "This ID is already registered."
                    else:
                        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
                        insert_query = "INSERT INTO users (user_id, name, password, role) VALUES (?, ?, ?, ?)"
                        cursor.execute(insert_query, (user_id, name, hashed_pw, role))
                        conn.commit()
                        return redirect(url_for('login', registered='true'))
                except sqlite3.Error as err:
                    print(f"DB Error: {err}")
                    message = "Database error occurred."
                finally:
                    conn.close()

    return render_template('register.html', message=message)

# --- LOGIN ROUTE ---
@app.route('/', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    message = ''
    if request.args.get('registered') == 'true':
        message = "Account created! Please login."

    if request.method == 'POST':
        user_id = request.form['student_id']
        input_password = request.form['password']

        conn = get_db_connection()
        if conn:
            cursor = conn.cursor()
            try:
                query = "SELECT password, name, role FROM users WHERE user_id = ?"
                cursor.execute(query, (user_id,))
                result = cursor.fetchone()

                if result:
                    # result is a Row object, access by index or key
                    stored_hash = result['password']
                    name = result['name']
                    role = result['role']

                    if check_password_hash(stored_hash, input_password):
                        session['user_id'] = user_id
                        session['name'] = name
                        session['role'] = role 
                        return redirect(url_for('dashboard'))
                    else:
                        message = "Invalid Password."
                else:
                    message = "User ID not found."

            except sqlite3.Error as err:
                print(f"Error: {err}")
                message = "System error."
            finally:
                conn.close()

    return render_template('login.html', message=message)

# --- DASHBOARD ROUTE (Student View) ---
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    role = session.get('role')

    if role == 'teacher':
        return redirect(url_for('teacher_portal'))

    total_assignments = 0
    total_classes = 0
    total_grade_points = 0.0
    graded_subjects = 0
    gpa = "N/A"
    
    classes_data = []

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor() # Row factory is already set in get_db_connection
        try:
            query = """
                SELECT u.name as teacher_name, e.grade, e.attendance, e.assignments_due 
                FROM enrollments e 
                JOIN users u ON e.teacher_id = u.user_id 
                WHERE e.student_id = ?
            """
            cursor.execute(query, (user_id,))
            classes_data = cursor.fetchall()

            total_classes = len(classes_data)

            for item in classes_data:
                total_assignments += item['assignments_due']
                
                grade = item['grade']
                if grade != 'N/A':
                    try:
                        total_grade_points += float(grade)
                        graded_subjects += 1
                    except ValueError:
                        pass
            
            if graded_subjects > 0:
                gpa = round(total_grade_points / graded_subjects, 2)

        except sqlite3.Error as err:
            print(f"Error: {err}")
        finally:
            conn.close()

    return render_template('dashboard.html', 
                           name=session['name'], 
                           student_id=user_id,
                           classes=classes_data,
                           gpa=gpa,
                           assignments_due=total_assignments,
                           total_classes=total_classes)

# --- TEACHER PORTAL ROUTE ---
@app.route('/teacher-dashboard')
def teacher_portal():
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect(url_for('login'))

    teacher_id = session['user_id']
    students_list = []
    
    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            query = """
                SELECT u.user_id, u.name, e.grade, e.attendance, e.assignments_due 
                FROM enrollments e 
                JOIN users u ON e.student_id = u.user_id 
                WHERE e.teacher_id = ?
            """
            cursor.execute(query, (teacher_id,))
            students_list = cursor.fetchall()
        except sqlite3.Error as err:
            print(f"Error: {err}")
        finally:
            conn.close()

    return render_template('teacher_dashboard.html', name=session['name'], students=students_list)

# --- UPDATE DETAILS ROUTE ---
@app.route('/update_details', methods=['POST'])
def update_details():
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect(url_for('login'))

    teacher_id = session['user_id']
    student_id = request.form['student_id']
    
    grade = request.form['grade']
    attendance = request.form['attendance']
    assignments = request.form['assignments']

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            query = """
                UPDATE enrollments 
                SET grade = ?, attendance = ?, assignments_due = ? 
                WHERE student_id = ? AND teacher_id = ?
            """
            cursor.execute(query, (grade, attendance, assignments, student_id, teacher_id))
            conn.commit()
        except sqlite3.Error as err:
            print(f"Update Error: {err}")
        finally:
            conn.close()

    return redirect(url_for('teacher_portal'))

# --- ADD STUDENT ROUTE ---
@app.route('/add_student', methods=['POST'])
def add_student():
    if 'user_id' not in session or session.get('role') != 'teacher':
        return redirect(url_for('login'))

    teacher_id = session['user_id']
    student_id_to_add = request.form['student_id']

    conn = get_db_connection()
    if conn:
        cursor = conn.cursor()
        try:
            # 1. Check if Student ID exists in users table
            check_query = "SELECT role FROM users WHERE user_id = ?"
            cursor.execute(check_query, (student_id_to_add,))
            user_result = cursor.fetchone()

            if user_result:
                # 2. Check if role is student
                if user_result['role'] == 'student':
                    # 3. Add to enrollments
                    insert_query = "INSERT INTO enrollments (teacher_id, student_id) VALUES (?, ?)"
                    cursor.execute(insert_query, (teacher_id, student_id_to_add))
                    conn.commit()
                    print("Student added successfully!")
                else:
                    print("Error: That ID belongs to a teacher, not a student.")
            else:
                print("Error: Student ID not found in database.")

        except sqlite3.Error as err:
            print(f"Database Error: {err}")
        finally:
            conn.close()

    return redirect(url_for('teacher_portal'))

# --- LOGOUT ROUTE ---
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


if __name__ == '__main__':
    # Initialize DB (Create tables) if they don't exist
    init_db()

    host_ip = get_local_ip()
    port = 5000

    print(f" \n --- SERVER STARTED (SQLITE MODE) ---")
    print(f" * Local:    http://127.0.0.1:{port}")
    print(f" * Network:  http://{host_ip}:{port}")
    print(f" ----------------------\n")

    app.run(debug=True, host='0.0.0.0', port=port)
