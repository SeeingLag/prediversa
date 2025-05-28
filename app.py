from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from datetime import datetime
from sqlalchemy import func

# Configuración inicial
app = Flask(__name__)
app.secret_key = 'tu_clave_secreta_prediversa'  # Cambiar en producción
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///prediversa.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Modelos (completos)
class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    nombre = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    rol = db.Column(db.String(20), default='estudiante')

class Cuestionario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    titulo = db.Column(db.String(100), nullable=False)
    descripcion = db.Column(db.Text)
    fecha_creacion = db.Column(db.DateTime, default=datetime.utcnow)
    preguntas = db.relationship('Pregunta', backref='cuestionario', lazy=True)

class Pregunta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.Text, nullable=False)
    tipo = db.Column(db.String(50), default='opcion_multiple')
    cuestionario_id = db.Column(db.Integer, db.ForeignKey('cuestionario.id'))
    opciones = db.relationship('Opcion', backref='pregunta', lazy=True)

class Opcion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    texto = db.Column(db.String(200), nullable=False)
    valor = db.Column(db.Integer)  # Puntaje de riesgo (1-5)
    pregunta_id = db.Column(db.Integer, db.ForeignKey('pregunta.id'))

class Respuesta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    pregunta_id = db.Column(db.Integer, db.ForeignKey('pregunta.id'))
    opcion_id = db.Column(db.Integer, db.ForeignKey('opcion.id'))
    fecha = db.Column(db.DateTime, default=datetime.utcnow)

class Alerta(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    usuario_id = db.Column(db.Integer, db.ForeignKey('usuario.id'))
    nivel_riesgo = db.Column(db.String(50))
    puntaje = db.Column(db.Integer)
    fecha = db.Column(db.DateTime, default=datetime.utcnow)
    revisada = db.Column(db.Boolean, default=False)
    acciones = db.Column(db.Text)
    usuario = db.relationship('Usuario', backref='alertas')

# Crear tablas y admin inicial
with app.app_context():
    db.create_all()
    if not Usuario.query.filter_by(username='admin').first():
        admin = Usuario(
            username='admin',
            nombre='Administrador',
            email='admin@prediversa.edu',
            password=generate_password_hash('admin123'),
            rol='admin'
        )
        db.session.add(admin)
        db.session.commit()

# Configuración Flask-Admin
admin = Admin(app, name='PrediVersa Admin', template_mode='bootstrap3', url='/admin')

# Decorador para admin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'usuario' not in session:
            flash('Acceso denegado: debe iniciar sesión', 'danger')
            return redirect(url_for('login'))
        user = Usuario.query.filter_by(username=session['usuario']).first()
        if not user or user.rol != 'admin':
            flash('Acceso denegado: se requiere rol de administrador', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Vistas de administración
class UsuarioModelView(ModelView):
    column_list = ['username', 'nombre', 'email', 'rol', 'alertas']
    form_columns = ['username', 'nombre', 'email', 'password', 'rol']
    column_searchable_list = ['username', 'email']

    def on_model_change(self, form, model, is_created):
        if is_created or form.password.data:
            model.password = generate_password_hash(form.password.data)

class AlertaModelView(ModelView):
    column_list = ['usuario', 'nivel_riesgo', 'puntaje', 'fecha', 'revisada']
    form_columns = ['usuario', 'nivel_riesgo', 'puntaje', 'revisada', 'acciones']
    column_searchable_list = ['usuario.nombre']

admin.add_view(UsuarioModelView(Usuario, db.session, name='Usuarios'))
admin.add_view(ModelView(Cuestionario, db.session, name='Cuestionarios', category='Diagnóstico'))
admin.add_view(ModelView(Pregunta, db.session, name='Preguntas', category='Diagnóstico'))
admin.add_view(ModelView(Opcion, db.session, name='Opciones', category='Diagnóstico'))
admin.add_view(AlertaModelView(Alerta, db.session, name='Alertas', category='Diagnóstico'))

# Funciones auxiliares
def evaluar_riesgo(usuario_id):
    puntaje = db.session.query(func.sum(Opcion.valor)).join(
        Respuesta, Respuesta.opcion_id == Opcion.id
    ).filter(Respuesta.usuario_id == usuario_id).scalar() or 0

    if puntaje > 15:
        nivel = "Alto riesgo"
    elif puntaje > 8:
        nivel = "Riesgo moderado"
    else:
        nivel = "Bajo riesgo"

    if nivel != "Bajo riesgo":
        alerta = Alerta(
            usuario_id=usuario_id,
            nivel_riesgo=nivel,
            puntaje=puntaje
        )
        db.session.add(alerta)
        db.session.commit()

    return nivel, puntaje

# =============================================
# RUTAS PRINCIPALES (Todas las esenciales)
# =============================================
@app.route("/")
def index():
    if 'usuario' in session:
        return redirect('/dashboard')
    return redirect(url_for('login'))

@app.route("/login", methods=['GET', 'POST'])
def login():
    if 'usuario' in session:
        return redirect('/dashboard')
    
    if request.method == 'POST':
        username = request.form.get('usuario', '').lower()
        password = request.form.get('contrasena', '')
        
        user = Usuario.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['usuario'] = user.username
            flash('Inicio de sesión exitoso', 'success')
            return redirect('/dashboard')
        flash('Usuario o contraseña incorrectos', 'danger')
    
    return render_template("index.html")

@app.route("/registrarse", methods=['GET', 'POST'])
def registrarse():
    if request.method == 'POST':
        username = request.form.get('usuario', '').strip().lower()
        email = request.form.get('email', '').strip()
        
        errores = []
        if Usuario.query.filter_by(username=username).first():
            errores.append("El usuario ya existe")
        if Usuario.query.filter_by(email=email).first():
            errores.append("El email ya está registrado")
        if len(request.form.get('contrasena', '')) < 6:
            errores.append("La contraseña debe tener mínimo 6 caracteres")
        if request.form.get('contrasena') != request.form.get('confirmar'):
            errores.append("Las contraseñas no coinciden")

        if not errores:
            new_user = Usuario(
                username=username,
                nombre=request.form.get('nombre', '').strip(),
                email=email,
                password=generate_password_hash(request.form.get('contrasena')),
                rol='estudiante'
            )
            db.session.add(new_user)
            db.session.commit()
            flash('¡Registro exitoso! Ahora puedes iniciar sesión', 'success')
            return redirect(url_for('login'))
        
        for error in errores:
            flash(error, 'danger')
    
    return render_template("registro.html")

@app.route("/olvide-contrasena", methods=['GET', 'POST'])
def olvide_contrasena():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        user = Usuario.query.filter_by(email=email).first()
        
        if user:
            flash('Se ha enviado un enlace de recuperación a tu email', 'info')
        else:
            flash('Si el email existe, recibirás un enlace de recuperación', 'info')
        
        return redirect(url_for('login'))
    
    return render_template("olvide_contrasena.html")

@app.route("/dashboard")
def dashboard():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    user = Usuario.query.filter_by(username=session['usuario']).first()
    if not user:
        flash('Usuario no encontrado', 'error')
        return redirect(url_for('logout'))
    
    return render_template("dashboard.html", usuario=user)

@app.route("/cuestionarios")
def listar_cuestionarios():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    cuestionarios = Cuestionario.query.all()
    return render_template("cuestionarios/listar.html", cuestionarios=cuestionarios)

@app.route("/cuestionario/<int:id>", methods=['GET', 'POST'])
def responder_cuestionario(id):
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    cuestionario = Cuestionario.query.get_or_404(id)
    usuario = Usuario.query.filter_by(username=session['usuario']).first()
    
    if request.method == 'POST':
        for key, value in request.form.items():
            if key.startswith('pregunta_'):
                pregunta_id = int(key.split('_')[1])
                respuesta = Respuesta(
                    usuario_id=usuario.id,
                    pregunta_id=pregunta_id,
                    opcion_id=int(value)
                )
                db.session.add(respuesta)
        db.session.commit()
        flash('¡Cuestionario completado!', 'success')
        return redirect(url_for('resultados'))
    
    return render_template("cuestionarios/responder.html", cuestionario=cuestionario)

@app.route("/resultados")
def resultados():
    if 'usuario' not in session:
        return redirect(url_for('login'))
    
    usuario = Usuario.query.filter_by(username=session['usuario']).first()
    nivel, puntaje = evaluar_riesgo(usuario.id)
    
    return render_template("resultados.html", 
                         nivel_riesgo=nivel,
                         puntaje=puntaje,
                         usuario=usuario)

@app.route("/logout")
def logout():
    session.pop('usuario', None)
    flash('Sesión cerrada correctamente', 'info')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
