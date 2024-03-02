from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'secret'
db = SQLAlchemy(app)

app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # Servidor de e-mail SMTP
app.config['MAIL_PORT'] = 465  # Porta do servidor SMTP
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'jcurityba@gmail.com'  # Seu e-mail
app.config['MAIL_PASSWORD'] = 'tvbwfcwjgzucenes'  # Sua senha de e-mail

mail = Mail(app)

login_manager = LoginManager()
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


#Rotas:
@app.route('/')
def index():
    return render_template('base.html')


SECRET_KEY = 'secret'
s = URLSafeTimedSerializer(SECRET_KEY)


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password_request():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = s.dumps({'user_id': user.id})
            
            msg = Message('Redefinição de Senha', sender='jcurityba@gmail.com', recipients=[email])
            msg.html = render_template('reset_email.html', token=token)  # Use o template de e-mail
            mail.send(msg)
            
            return "Instruções de redefinição de senha enviadas para o seu e-mail."
        else:
            return "Usuário não encontrado."
    return render_template('reset_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        data = s.loads(token)
        user_id = data['user_id']
        user = User.query.get(user_id)
    except SignatureExpired:
        return "Token expirado."
    except BadSignature:
        return "Token inválido."
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        hashed_password = generate_password_hash(new_password, method='sha256')
        user.password = hashed_password
        db.session.commit()
        return "Senha redefinida com sucesso."
    
    return render_template('reset_password_form.html', token=token)


@app.route('/home')
@login_required
def home():
    return render_template('home.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashed_password = generate_password_hash(password, method='sha256')
        new_user = User(username=username, password=hashed_password, email=email)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('register'))
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            return "Credenciais inválidas"
    return render_template('login.html')


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        
        user = User.query.get(current_user.id)
        
        if user and check_password_hash(user.password, current_password):
            hashed_new_password = generate_password_hash(new_password, method='sha256')
            user.password = hashed_new_password
            db.session.commit()
            return redirect(url_for('home'))
        else:
            return "Senha atual incorreta"
    
    return render_template('change_password.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/users')
@login_required
def users():
    all_users = User.query.all()
    return render_template('users.html', users=all_users)


@app.route('/delete_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        return redirect(url_for('users'))
    return render_template('index.html')


@app.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def update_user(user_id):
    user = User.query.get(user_id)
    if user:
        if request.method == 'POST':
            new_username = request.form['new_username']
            new_password = request.form['new_password']
            new_email = request.form['new_email']
            
            # Atualizar nome de usuário, se fornecido
            if new_username:
                user.username = new_username

            # Atualizar senha, se fornecida
            if new_password:
                hashed_password = generate_password_hash(new_password, method='sha256')
                user.password = hashed_password

            if new_email:
                user.email = new_email
            
            db.session.commit()
            return redirect(url_for('users'))
        
        return render_template('edit_users.html', user=user)
    return render_template('users.html')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)  # Adicione esta linha


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Banco de dados criado!")
        app.run(debug=True)

