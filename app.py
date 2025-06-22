import streamlit as st
import os, uuid, io
import qrcode
import pyotp
from passlib.context import CryptContext
from sqlalchemy.exc import OperationalError
from sqlalchemy import text
from database import SessionLocal, engine, Base
from models import User, Link

# --- Session state defaults ---
if 'page' not in st.session_state:
    st.session_state.page = 'main'
if 'edit_id' not in st.session_state:
    st.session_state.edit_id = None

# --- Page config and CSS ---
st.set_page_config(page_title="Meus Links Úteis", layout="wide")
st.markdown("""
<style>
body { background-color: #f8f9fa; }
.link-title { font-size: 1.4rem; color: #2E8B57; font-weight: bold; margin-bottom: 0.3rem; }
.card { border: 1px solid #e1e1e1; padding: 1rem; border-radius: 1rem; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 1rem; background: #fff; }
</style>
""", unsafe_allow_html=True)

# --- Database setup & migration ---
Base.metadata.create_all(bind=engine)
with engine.connect() as conn:
    try:
        conn.execute(text("SELECT is_admin FROM users LIMIT 1"))
    except OperationalError:
        conn.execute(text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN NOT NULL DEFAULT 0"))

# --- Security helpers ---
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
def hash_password(p): return pwd_context.hash(p)
def verify_password(plain, hashed): return pwd_context.verify(plain, hashed)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- Ensure default admin exists ---
ADMIN_USER, ADMIN_PWD = "administrador", "Th31tD0ntF41l"
try:
    db0 = next(get_db())
    if not db0.query(User).filter(User.username == ADMIN_USER).one_or_none():
        secret = pyotp.random_base32()
        admin = User(username=ADMIN_USER, password_hash=hash_password(ADMIN_PWD), totp_secret=secret, is_admin=True)
        db0.add(admin)
        db0.commit()
except:
    pass

# --- Session persistence via URL query params ---
qp = st.query_params
if 'user_id' in qp:
    try:
        st.session_state.user_id = int(qp['user_id'][0])
    except:
        st.session_state.user_id = None
elif 'user_id' not in st.session_state:
    st.session_state.user_id = None

# --- Login + 2FA flow ---
if st.session_state.user_id is None:
    st.sidebar.header("🔑 Login")
    usr = st.sidebar.text_input("Usuário", key="login_user")
    pwd = st.sidebar.text_input("Senha", type="password", key="login_pass")
    if st.sidebar.button("Entrar"):
        db1 = next(get_db())
        user_obj = db1.query(User).filter(User.username == usr).first()
        if user_obj and verify_password(pwd, user_obj.password_hash):
            st.session_state.tmp_user = user_obj.id
            uri = pyotp.TOTP(user_obj.totp_secret).provisioning_uri(name=usr, issuer_name="MeuAppLinks")
            buf = io.BytesIO()
            qrcode.make(uri).save(buf, format="PNG")
            st.sidebar.image(buf, caption="Escaneie para configurar 2FA")
        else:
            st.sidebar.error("Usuário ou senha inválidos.")
    if 'tmp_user' in st.session_state:
        code = st.sidebar.text_input("Código 2FA", key="login_2fa")
        if st.sidebar.button("Validar 2FA"):
            db2 = next(get_db())
            usr2 = db2.query(User).get(st.session_state.tmp_user)
            if usr2 and pyotp.TOTP(usr2.totp_secret).verify(code):
                st.session_state.user_id = usr2.id
                # persiste user_id na URL usando nova API
                st.query_params = {"user_id": [str(usr2.id)]}
                del st.session_state['tmp_user']
                st.sidebar.success("Login realizado com sucesso!")
                st.rerun()
            else:
                st.sidebar.error("Código 2FA inválido.")
    st.stop()

# --- Retrieve current user ---
db_main = next(get_db())
current_user = db_main.query(User).get(st.session_state.user_id)

# --- Logout ---
if st.sidebar.button("🚪 Logout"):
    st.session_state.user_id = None
    st.session_state.page = 'main'
    # limpa todos os query params usando nova API
    st.query_params = {}
    st.sidebar.success("Você saiu com sucesso.")
    st.rerun()

# --- Full-screen Edit Overlay ---
if st.session_state.page == 'edit':
    db_edit = next(get_db())
    link = db_edit.query(Link).get(st.session_state.edit_id)
    st.header("✏️ Editar Link")
    with st.form("edit_form"):
        title = st.text_input("Título", link.title)
        url = st.text_input("URL", link.url)
        desc = st.text_area("Descrição", link.description)
        img = st.file_uploader("Nova Imagem", type=["png","jpg","jpeg"])
        submitted = st.form_submit_button("Salvar Alterações")
        if submitted:
            # validate
            if not title.strip() or not url.strip():
                st.error("Título e URL são obrigatórios.")
            elif db_edit.query(Link).filter(Link.id != link.id, (Link.title == title) | (Link.url == url)).first():
                st.error("Título ou URL já existe para outro link.")
            else:
                link.title, link.url, link.description = title, url, desc
                if img:
                    ext = img.name.split('.')[-1]
                    fn = f"{uuid.uuid4()}.{ext}"
                    os.makedirs('uploads', exist_ok=True)
                    path = os.path.join('uploads', fn)
                    with open(path, 'wb') as f:
                        f.write(img.getbuffer())
                    link.image_path = path
                db_edit.commit()
                st.success("Link atualizado com sucesso!")
                st.session_state.page = 'main'
                st.rerun()
    if st.button("Cancelar"):
        st.session_state.page = 'main'
        st.rerun()
    st.stop()

# --- Main Interface ---
st.title("Meus Links Úteis")
if current_user.is_admin:
    choice = st.sidebar.radio("Admin Panel", ["Cadastrar Usuário", "Gerenciar Usuários", "Links"])
    if choice == "Cadastrar Usuário":
        st.header("➕ Cadastrar Novo Usuário")
        nu = st.text_input("Usuário")
        npw = st.text_input("Senha", type="password")
        na = st.checkbox("Conceder permissão de admin")
        if st.button("Criar Conta"):
            if not nu.strip() or not npw.strip():
                st.error("Usuário e senha são obrigatórios.")
            else:
                dbu = next(get_db())
                if dbu.query(User).filter(User.username == nu).first():
                    st.error("Usuário já existe.")
                else:
                    sec = pyotp.random_base32()
                    newu = User(username=nu, password_hash=hash_password(npw), totp_secret=sec, is_admin=na)
                    dbu.add(newu); dbu.commit(); st.success(f"Usuário '{nu}' criado.")
    elif choice == "Gerenciar Usuários":
        st.header("🔧 Gerenciar Usuários")
        dbu = next(get_db())
        for u in dbu.query(User).all():
            is_master = (u.username == ADMIN_USER)
            c1, c2, c3 = st.columns([3,1,1])
            c1.write(f"**{u.username}** {'(admin)' if u.is_admin else ''}")
            p = c1.text_input("Nova senha", type="password", key=f"pwd_{u.id}")
            if c1.button("Atualizar", key=f"btnpwd_{u.id}") and p.strip():
                u.password_hash = hash_password(p); dbu.commit(); st.success("Senha atualizada.")
            val = u.is_admin
            newval = c2.checkbox("Admin", value=val, disabled=is_master, key=f"adm_{u.id}")
            if not is_master and newval != val:
                u.is_admin = newval; dbu.commit(); st.success("Permissão alterada.")
            if not is_master and c3.button("Excluir usuário", key=f"del_user_{u.id}"):
                dbu.delete(u); dbu.commit(); st.success(f"Usuário {u.username} excluído."); st.rerun()
    else:
        st.header("📚 Links do Sistema")
        dbu = next(get_db())
        with st.expander("➕ Adicionar link (Admin)", expanded=True):
            with st.form("form_add_admin"):
                t = st.text_input("Título")
                u = st.text_input("URL")
                d = st.text_area("Descrição")
                f = st.file_uploader("Imagem", type=["png","jpg","jpeg"])
                if st.form_submit_button("Salvar"):
                    if not t.strip() or not u.strip():
                        st.error("Título e URL são obrigatórios.")
                    elif dbu.query(Link).filter((Link.title == t) | (Link.url == u)).first():
                        st.error("Título ou URL já existe.")
                    else:
                        ip = None
                        if f:
                            ext = f.name.split('.')[-1]
                            fn = f"{uuid.uuid4()}.{ext}"
                            os.makedirs('uploads', exist_ok=True)
                            pth = os.path.join('uploads', fn)
                            with open(pth, 'wb') as fh:
                                fh.write(f.getbuffer())
                            ip = pth
                        nl = Link(user_id=current_user.id, title=t, url=u, description=d, image_path=ip)
                        dbu.add(nl); dbu.commit(); st.success("Link cadastrado.")
        links = dbu.query(Link).all()
        cols = st.columns(2)
        for i, ln in enumerate(links):
            c = cols[i % 2]
            with c:
                st.markdown(f"<div class='card'><div class='link-title'>{ln.title}</div><p>{ln.description}</p></div>", unsafe_allow_html=True)
                if st.button("Editar", key=f"edit_admin_{ln.id}"):
                    st.session_state.edit_id = ln.id; st.session_state.page = 'edit'; st.rerun()
                if st.button("Excluir", key=f"del_admin_{ln.id}"):
                    dbu.delete(ln); dbu.commit(); st.rerun()
else:
    st.subheader("📚 Meus Links")
    dbu = next(get_db())
    search = st.text_input("🔍 Buscar links", key="search")
    with st.expander("➕ Adicionar link", expanded=True):
        with st.form("form_add"):
            t = st.text_input("Título")
            u = st.text_input("URL")
            d = st.text_area("Descrição")
            f = st.file_uploader("Imagem", type=["png","jpg","jpeg"])
            if st.form_submit_button("Salvar"):
                if not t.strip() or not u.strip():
                    st.error("Título e URL obrigatórios.")
                elif dbu.query(Link).filter((Link.title == t) | (Link.url == u)).first():
                    st.error("Título ou URL já existe.")
                else:
                    ip = None
                    if f:
                        ext = f.name.split('.')[-1]
                        fn = f"{uuid.uuid4()}.{ext}"
                        os.makedirs('uploads', exist_ok=True)
                        pth = os.path.join('uploads', fn)
                        with open(pth, 'wb') as fh:
                            fh.write(f.getbuffer())
                        ip = pth
                    nl = Link(user_id=current_user.id, title=t, url=u, description=d, image_path=ip)
                    dbu.add(nl); dbu.commit(); st.success("Link cadastrado.")
    links = dbu.query(Link).all()
    filtered = [ln for ln in links if search.lower() in ln.title.lower() or search.lower() in (ln.description or "").lower()]
    cols = st.columns(2)
    for i, ln in enumerate(filtered):
        c = cols[i % 2]
        with c:
            st.markdown(f"<div class='card'><a href='{ln.url}' target='_blank' class='link-title'>{ln.title}</a><p>{ln.description}</p></div>", unsafe_allow_html=True)
            if st.button("Editar", key=f"edit_user_{ln.id}"):
                st.session_state.edit_id = ln.id; st.session_state.page = 'edit'; st.rerun()
