from flask import render_template, request, redirect,url_for,flash
from flask_login import login_user,logout_user,current_user,login_required
from models import User,Role

def register_routes(app, db,bcrypt):

    @app.route('/')
    def index():
        return render_template('index.html')
        
        
    @app.route('/signup',methods=['GET','POST'])
    def signup():
        if request.method == 'GET':
            return render_template('signup.html')
        elif request.method == 'POST':
            try :                
                username = request.form.get('username')
                password= request.form.get('password')
                email= request.form.get('email')
                hash_password = bcrypt.generate_password_hash(password).decode('utf-8')
                
                first_user = User.query.first()
                if first_user is None:  
                    role = Role.ADMIN
                else:
                    role = Role.USER
    
                user = User(username=username, password=hash_password, email=email, role=role)
                db.session.add(user)
                db.session.commit()
                user = User.query.all()
                return redirect( url_for('index') )
            
            except Exception as e:
                db.session.rollback()
                flash(f'Erreur lors de l\'inscription: {e}', 'error')
                return render_template('signup.html')

    @app.route('/login',methods=['GET','POST'])
    def login():
        if request.method == 'GET':
            return render_template('login.html')
        elif request.method == 'POST':
            username = request.form.get('username')
            password= request.form.get('password')
            
            user= User.query.filter(User.username == username).first()

            if user and bcrypt.check_password_hash(user.password, password):
               login_user(user)
               flash('Connexion réussie.', 'success')
               return redirect(url_for('index'))  
            else:
                flash('Nom d\'utilisateur ou mot de passe incorrect.', 'error')
                return render_template('login.html', error='Invalid credentials')


            

    @app.route('/logout')
    def logout():
        logout_user()
        return redirect( url_for('index') )
    
    @app.route('/secret')
    @login_required
    def secret():
        return 'My secret message'