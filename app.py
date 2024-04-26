from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, json
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.sql import text
from sqlalchemy.exc import NoResultFound
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous.url_safe import URLSafeSerializer as Serializer
from flask_mail import Mail, Message
import os
import time
from decouple import config

app = Flask(__name__)
app.config['SECRET_KEY'] = config('SECRET_KEY', default='logic2008@')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///logic.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = config('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = config('MAIL_PASSWORD')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg'}

mail = Mail(app)
db = SQLAlchemy(app)

class Empresa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    link_financeiro = db.Column(db.String(200), nullable=True)
    link_vendas = db.Column(db.String(200), nullable=True)
    link_estoque = db.Column(db.String(200), nullable=True)
    link_clientes = db.Column(db.String(200), nullable=True)
    link_rh = db.Column(db.String(200), nullable=True)
    imagem_url = db.Column(db.String(300), nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "nome": self.nome,
            "link_financeiro": self.link_financeiro,
            "link_vendas": self.link_vendas,
            "link_estoque": self.link_estoque,
            "link_clientes": self.link_clientes,
            "link_rh": self.link_rh,
            "imagem_url": self.imagem_url
        }

    def __repr__(self):
        return f'<Empresa {self.nome}>'

class Usuario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    senha_hash = db.Column(db.String(128), nullable=False)
    tipo = db.Column(db.String(10), nullable=False)
    empresa_id = db.Column(db.Integer, db.ForeignKey('empresa.id'), nullable=True)

    empresa = db.relationship('Empresa', backref=db.backref('usuarios', lazy=True))

    def get_reset_password_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'])
        timestamp = int(time.time() + expires_sec)
        return s.dumps({'user_id': self.id, 'exp': timestamp})

    def __repr__(self):
        return f'<Usuario {self.nome}, Empresa ID: {self.empresa_id}>'

    @staticmethod
    def verify_reset_password_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
            if data['exp'] < int(time.time()):
                return None
            user_id = data['user_id']
        except:
            return None
        return Usuario.query.get(user_id)

def adicionar_usuario(nome, email, senha, tipo, empresa_id=None):
    usuario_existente = Usuario.query.filter_by(email=email).first()
    if usuario_existente:
        print("Erro: Usuário com este e-mail já existe.")
        return False
    if empresa_id:
        empresa_id = int(empresa_id)  # Converte o ID da empresa de string para int
    novo_usuario = Usuario(nome=nome, email=email, senha_hash=generate_password_hash(senha), tipo=tipo, empresa_id=empresa_id)
    db.session.add(novo_usuario)
    try:
        db.session.commit()
        return True
    except Exception as e:
        db.session.rollback()
        print(f"Erro ao adicionar usuário: {e}")
        return False

def add_email_column_if_not_exists():
    with app.app_context():
        if 'email' not in [column.name for column in Usuario.__table__.columns]:
            db.engine.execute(text('ALTER TABLE usuario ADD COLUMN email VARCHAR(100) UNIQUE'))

def send_reset_email(usuario):
    token = usuario.get_reset_password_token()
    msg = Message('Redefinir Senha',
                  sender='noreply@centralsystemlogic.com',
                  recipients=[usuario.email])
    msg.body = f'''Para redefinir sua senha, visite o seguinte link:
{url_for('reset_password', token=token, _external=True)}

Se você não fez essa solicitação, simplesmente ignore este e-mail e nenhuma alteração será feita.
'''
    mail.send(msg)

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        usuario = request.form.get('usuario')
        senha = request.form.get('senha')
        try:
            usuario_info = Usuario.query.filter_by(nome=usuario).one()
            if check_password_hash(usuario_info.senha_hash, senha):
                session['usuario'] = usuario_info.nome
                session['tipo'] = usuario_info.tipo
                session['empresa'] = usuario_info.empresa.to_dict() if usuario_info.empresa else None
                session['email'] = usuario_info.email
                flash('Bem-vindo à Logic!', 'success')
                return redirect(url_for('menu'))
            else:
                flash('Usuário ou senha incorretos!', 'error')
        except NoResultFound:
            flash('Usuário ou senha incorretos!', 'error')
    return render_template('login.html')

# Continue com as demais rotas e lógicas de negócios conforme necessário...


@app.route('/menu')
def menu():
    if 'usuario' not in session:
        flash('Você precisa estar logado para acessar esta página.', 'info')
        return redirect(url_for('login'))
    return render_template('menu.html', tipo=session.get('tipo'))

@app.route('/adicionar_empresa', methods=['GET', 'POST'])
def adicionar_empresa():
    if 'usuario' not in session or session.get('tipo') != 'admin':
        
        return jsonify({'error': 'Acesso restrito'}), 403

    if request.method == 'POST':
        nome_empresa = request.form['nome']
        link_financeiro = request.form['link_financeiro']
        link_vendas = request.form['link_vendas']
        link_estoque = request.form['link_estoque']
        link_clientes = request.form['link_clientes']
        link_rh = request.form['link_rh']
        imagem = request.files['imagem']

        if imagem and allowed_file(imagem.filename):
            filename = secure_filename(imagem.filename)
            imagem.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            imagem_url = url_for('static', filename='uploads/' + filename)
        else:
            imagem_url = None

        nova_empresa = Empresa(
            nome=nome_empresa, link_financeiro=link_financeiro, link_vendas=link_vendas,
            link_estoque=link_estoque, link_clientes=link_clientes, link_rh=link_rh, imagem_url=imagem_url
        )
        db.session.add(nova_empresa)
        db.session.commit()

        
        return jsonify({'success': 'Empresa adicionada com sucesso', 'empresa_id': nova_empresa.id})

  
    return render_template('adicionarempresas.html')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/empresas')
def empresas():
    try:
        if 'usuario' not in session:
            flash('Você precisa estar logado para acessar esta página.', 'info')
            return redirect(url_for('login'))

        user_type = session.get('tipo')
        user_empresa = session.get('empresa')  # Supondo que isso deva ser uma string

        # Certifique-se de que estamos trabalhando com uma string
        if isinstance(user_empresa, dict):
            user_empresa = user_empresa.get('nome')  # Ajuste conforme o formato do seu dicionário

        if user_type == 'empresa':
            # Filtra para mostrar apenas a empresa do usuário se ele for do tipo 'empresa'
            empresas = Empresa.query.filter(Empresa.nome == user_empresa).all()
        else:
            empresas = Empresa.query.all()

        empresas_info = [{
            'id': empresa.id,
            'nome': empresa.nome,
            'link_financeiro': empresa.link_financeiro,
            'link_vendas': empresa.link_vendas,
            'link_estoque': empresa.link_estoque,
            'link_clientes': empresa.link_clientes,
            'link_rh': empresa.link_rh,
            'imagem_url': empresa.imagem_url if empresa.imagem_url else url_for('static', filename='default-company.png')
        } for empresa in empresas]

        return render_template('empresas.html', empresas=empresas_info)
    except Exception as e:
        app.logger.error(f"Erro na rota /empresas: {str(e)}")
        flash('Erro ao carregar as empresas.', 'error')
        return render_template('error.html'), 500

@app.route('/gerenciar_empresas')
def gerenciar_empresas():
    if 'usuario' not in session or session.get('tipo') != 'admin':
        flash('Acesso restrito.', 'error')
        return redirect(url_for('login'))
    todas_empresas = Empresa.query.all()
    return render_template('gerenciarempresas.html', empresas=todas_empresas)

@app.route('/gerenciar_empresas/editar/<int:id>', methods=['GET', 'POST'])
def editar_empresa(id):
    if 'usuario' not in session or session.get('tipo') != 'admin':
        flash('Acesso restrito.', 'error')
        return redirect(url_for('login'))
    
    empresa = Empresa.query.get_or_404(id)

    if request.method == 'POST':
        empresa.nome = request.form['nome']
        empresa.link_financeiro = request.form.get('link_financeiro')
        empresa.link_vendas = request.form.get('link_vendas')
        empresa.link_estoque = request.form.get('link_estoque')
        empresa.link_clientes = request.form.get('link_clientes')
        empresa.link_rh = request.form.get('link_rh')

        # Tratar o upload da imagem
        imagem = request.files['imagem']
        if imagem and allowed_file(imagem.filename):
            filename = secure_filename(imagem.filename)
            imagem.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            # Atualiza a URL da imagem no banco de dados
            empresa.imagem_url = url_for('static', filename='uploads/' + filename, _external=True)

        db.session.commit()
        flash('Empresa editada com sucesso!', 'success')
        return redirect(url_for('gerenciar_empresas'))

    return render_template('editarempresa.html', empresa=empresa)



@app.route('/gerenciar_empresas/excluir/<int:id>', methods=['GET', 'POST'])
def excluir_empresa(id):
    if 'usuario' not in session or session.get('tipo') != 'admin':
        flash('Acesso restrito.', 'error')
        return redirect(url_for('login'))
    empresa = Empresa.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(empresa)
        db.session.commit()
        flash('Empresa excluída com sucesso!', 'success')
        return redirect(url_for('gerenciar_empresas'))
    return render_template('excluirempresa.html', empresa=empresa)

@app.route('/atendimento')
def atendimento():
    if 'usuario' not in session or (session['tipo'] not in ['geral', 'empresa', 'admin']):
        flash('Acesso restrito.', 'error')
        return redirect(url_for('login'))
    return render_template('atendimento.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Você saiu com sucesso.', 'info')
    return redirect(url_for('login'))

@app.route('/cadastrar_usuario', methods=['GET', 'POST'])
def cadastrar_usuario():
    if 'usuario' not in session or session.get('tipo') != 'admin':
        flash('Acesso restrito.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']
        senha = request.form['senha']
        tipo = request.form['tipo']
        empresa_id = request.form.get('empresa', None)  # Garante que None é usado se o campo estiver vazio

        print("Raw empresa_id received:", empresa_id)  # Log para debugar

        if empresa_id and empresa_id.isdigit():  # Checa se é um dígito e não está vazio
            empresa_id = int(empresa_id)
        else:
            empresa_id = None

        print("Processed empresa_id:", empresa_id)  # Log após processamento

        if Usuario.query.filter_by(email=email).first():
            flash('E-mail já cadastrado!', 'error')
            return redirect(url_for('cadastrar_usuario'))

        novo_usuario = Usuario(
            nome=nome,
            email=email,
            senha_hash=generate_password_hash(senha),
            tipo=tipo,
            empresa_id=empresa_id
        )
        db.session.add(novo_usuario)
        try:
            db.session.commit()
            flash('Usuário cadastrado com sucesso!', 'success')
            return redirect(url_for('cadastrar_usuario'))
        except Exception as e:
            db.session.rollback()
            flash(f'Falha ao cadastrar usuário. Erro: {e}', 'error')
        
    empresas = Empresa.query.all()
    return render_template('cadastrarusuario.html', empresas=empresas)


@app.route('/gerenciar_usuarios')
def gerenciar_usuarios():
    if 'usuario' not in session or session.get('tipo') != 'admin':
        flash('Acesso restrito.', 'error')
        return redirect(url_for('login'))
    todos_usuarios = Usuario.query.all()
    empresas = Empresa.query.all()
    return render_template('gerenciarusuarios.html', usuarios=todos_usuarios, empresas=empresas)

@app.route('/gerenciar_usuarios/editar/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):
    if 'usuario' not in session or session.get('tipo') != 'admin':
        flash('Acesso restrito.', 'error')
        return redirect(url_for('login'))
    usuario = Usuario.query.get_or_404(id)
    if request.method == 'POST':
        usuario.nome = request.form['nome']
        usuario.email = request.form['email']
        usuario.tipo = request.form['tipo']
        usuario.empresa = request.form.get('empresa', None)
        db.session.commit()
        flash('Usuário editado com sucesso!', 'success')
        return redirect(url_for('gerenciar_usuarios'))
    return render_template('editarusuario.html', usuario=usuario)

@app.route('/gerenciar_usuarios/excluir/<int:id>', methods=['GET', 'POST'])
def excluir_usuario(id):
    if 'usuario' not in session or session.get('tipo') != 'admin':
        flash('Acesso restrito.', 'error')
        return redirect(url_for('login'))
    usuario = Usuario.query.get_or_404(id)
    if request.method == 'POST':
        db.session.delete(usuario)
        db.session.commit()
        flash('Usuário excluído com sucesso!', 'success')
        return redirect(url_for('gerenciar_usuarios'))
    return render_template('excluirusuario.html', usuario=usuario)

@app.route('/esqueceu_senha', methods=['GET', 'POST'])
def esqueceu_senha():
    if request.method == 'POST':
        email_usuario = request.form.get('email')
        usuario = Usuario.query.filter_by(email=email_usuario).first()
        if usuario:
            send_reset_email(usuario)
            flash('Um e-mail foi enviado com instruções para redefinir sua senha.', 'info')
            return redirect(url_for('login'))
        else:
            flash('Não existe uma conta com este e-mail.', 'error')
    return render_template('esqueceu_senha.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    usuario = Usuario.verify_reset_password_token(token)
    if not usuario:
        flash('O token é inválido ou expirou.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        nova_senha = request.form.get('password')
        if nova_senha:
            usuario.senha_hash = generate_password_hash(nova_senha)
            db.session.commit()
            flash('Sua senha foi redefinida!', 'success')
            return redirect(url_for('login'))
        else:
            flash('Por favor, insira uma nova senha.', 'error')
    return render_template('reset_password.html')

@app.route('/enviar_mensagem', methods=['POST'])
def enviar_mensagem():
    if 'usuario' not in session or 'email' not in session:
        return jsonify({'error': 'Usuário não autenticado ou e-mail não disponível'}), 401

    mensagem = request.form.get('mensagem')
    if not mensagem:
        return jsonify({'error': 'Mensagem vazia'}), 400

    sender_email = session['email']
    recipient_email = 'centralsystemlogic@gmail.com'  
    msg = Message('Nova Mensagem de Suporte', sender=sender_email, recipients=[recipient_email])
    msg.body = f'Mensagem de {session["usuario"]} ({sender_email}): {mensagem}'
    
    return jsonify({'success': 'Mensagem enviada com sucesso! Verifique o seu email que nossa equipe irá entrar em contato.'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        add_email_column_if_not_exists()
        adicionar_usuario('Leandro', 'utamcgoiania@gmail.com', '234', 'admin')
    app.run(debug=True)
