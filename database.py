import sqlite3
from werkzeug.security import generate_password_hash

connection = sqlite3.connect('database.db')
cursor = connection.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'Сотрудник'
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    booking_date TEXT NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT NOT NULL,
    FOREIGN KEY (room_id) REFERENCES rooms (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
)
''')


cursor.execute("SELECT * FROM users WHERE username = 'admin'")
if cursor.fetchone() is None:
    # Хэшируем пароль
    hashed_password = generate_password_hash('admin', method='pbkdf2:sha256')
    cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                   ('admin', hashed_password, 'Администратор'))
    print("Пользователь 'admin' создан.")


cursor.execute("SELECT * FROM rooms WHERE name IN ('Переговорная №1', 'Конференц-зал \"Космос\"')")
if len(cursor.fetchall()) == 0:
    cursor.execute("INSERT INTO rooms (name, description) VALUES (?, ?)",
                   ('Переговорная №1', 'Маленькая комната на 4 человека с доской.'))
    cursor.execute("INSERT INTO rooms (name, description) VALUES (?, ?)",
                   ('Конференц-зал "Космос"', 'Большой зал на 20 человек с проектором.'))
    print("Тестовые комнаты созданы.")

connection.commit()
connection.close()

print("База данных создана")