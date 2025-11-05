import sqlite3
from flask import Flask, render_template, request, redirect, url_for, g, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'a-very-secret-key-that-no-one-will-guess'
DATABASE = 'database.db'

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # Позволяет обращаться к колонкам по имени
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

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
        if 'user_id' not in session or session.get('user_role') != 'Администратор':
            flash('Доступ запрещен. Требуются права администратора.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        db = get_db()
        # Проверка, что имя пользователя не занято
        if db.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone() is not None:
            flash('Это имя пользователя уже занято.', 'danger')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
        db.commit()
        
        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()

        if user and check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['user_name'] = user['username']
            session['user_role'] = user['role']
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
def index():
    db = get_db()
    rooms = db.execute('SELECT * FROM rooms').fetchall()
    bookings = db.execute('''
        SELECT b.*, u.username, r.name as room_name 
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN rooms r ON b.room_id = r.id
        ORDER BY b.booking_date, b.start_time
    ''').fetchall()
    return render_template('index.html', rooms=rooms, bookings=bookings)

@app.route('/book/<int:room_id>', methods=['GET', 'POST'])
@login_required
def book_room(room_id):
    db = get_db()
    room = db.execute('SELECT * FROM rooms WHERE id = ?', (room_id,)).fetchone()

    if request.method == 'POST':
        date = request.form['date']
        start_time = request.form['start_time']
        end_time = request.form['end_time']
        user_id = session['user_id']

        # Простая проверка на пересечение времени (для реального проекта нужна сложнее)
        existing_booking = db.execute(
            'SELECT id FROM bookings WHERE room_id = ? AND booking_date = ? AND start_time < ? AND end_time > ?',
            (room_id, date, end_time, start_time)
        ).fetchone()

        if existing_booking:
            flash('Это время уже занято. Пожалуйста, выберите другое.', 'danger')
        else:
            db.execute('INSERT INTO bookings (room_id, user_id, booking_date, start_time, end_time) VALUES (?, ?, ?, ?, ?)',
                       (room_id, user_id, date, start_time, end_time))
            db.commit()
            flash('Комната успешно забронирована!', 'success')
            return redirect(url_for('index'))

    return render_template('book_room.html', room=room)

@app.route('/dashboard')
@login_required
def user_dashboard():
    db = get_db()
    user_id = session['user_id']
    my_bookings = db.execute('''
        SELECT b.*, r.name as room_name 
        FROM bookings b 
        JOIN rooms r ON b.room_id = r.id 
        WHERE b.user_id = ? 
        ORDER BY b.booking_date, b.start_time
    ''', (user_id,)).fetchall()
    return render_template('user_dashboard.html', bookings=my_bookings)

@app.route('/cancel_booking/<int:booking_id>', methods=['POST'])
@login_required
def cancel_booking(booking_id):
    db = get_db()
    booking = db.execute('SELECT * FROM bookings WHERE id = ?', (booking_id,)).fetchone()
    
    if booking and (booking['user_id'] == session['user_id'] or session['user_role'] == 'Администратор'):
        db.execute('DELETE FROM bookings WHERE id = ?', (booking_id,))
        db.commit()
        flash('Бронирование успешно отменено.', 'success')
    else:
        flash('У вас нет прав для отмены этого бронирования.', 'danger')
        
    if request.referrer and 'admin' in request.referrer:
         return redirect(url_for('admin_dashboard'))
    return redirect(url_for('user_dashboard'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    db = get_db()
    rooms = db.execute('SELECT * FROM rooms').fetchall()
    bookings = db.execute('''
        SELECT b.*, u.username, r.name as room_name 
        FROM bookings b
        JOIN users u ON b.user_id = u.id
        JOIN rooms r ON b.room_id = r.id
        ORDER BY b.booking_date, b.start_time
    ''').fetchall()
    return render_template('admin_dashboard.html', rooms=rooms, bookings=bookings)

@app.route('/admin/room/add', methods=['POST'])
@admin_required
def add_room():
    name = request.form['name']
    description = request.form['description']
    if name:
        db = get_db()
        db.execute('INSERT INTO rooms (name, description) VALUES (?, ?)', (name, description))
        db.commit()
        flash('Комната успешно добавлена.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/room/edit/<int:room_id>', methods=['POST'])
@admin_required
def edit_room(room_id):
    name = request.form['name']
    description = request.form['description']
    if name:
        db = get_db()
        db.execute('UPDATE rooms SET name = ?, description = ? WHERE id = ?', (name, description, room_id))
        db.commit()
        flash('Информация о комнате обновлена.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/room/delete/<int:room_id>', methods=['POST'])
@admin_required
def delete_room(room_id):
    db = get_db()
    # Сначала удаляем все бронирования, связанные с этой комнатой
    db.execute('DELETE FROM bookings WHERE room_id = ?', (room_id,))
    # Затем удаляем саму комнату
    db.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
    db.commit()
    flash('Комната и все связанные с ней бронирования удалены.', 'warning')
    return redirect(url_for('admin_dashboard'))


if __name__ == '__main__':
    app.run(debug=True)