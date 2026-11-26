import os, secrets, uuid
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import qrcode

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
QR_DIR = os.path.join(BASE_DIR, "static", "qr")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(QR_DIR, exist_ok=True)

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-secret-key-before-deployment")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "project.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
ALLOWED = {"pdf", "png", "jpg", "jpeg"}

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="candidate")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    profile = db.relationship("Profile", backref="user", uselist=False, cascade="all, delete-orphan")

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), unique=True)
    dob = db.Column(db.String(30)); gender = db.Column(db.String(30))
    phone = db.Column(db.String(30)); street = db.Column(db.String(200))
    city = db.Column(db.String(100)); state = db.Column(db.String(100))
    country = db.Column(db.String(100)); pincode = db.Column(db.String(20))
    college = db.Column(db.String(150)); degree = db.Column(db.String(100))
    department = db.Column(db.String(100)); university = db.Column(db.String(150))
    graduation_year = db.Column(db.String(10)); cgpa = db.Column(db.String(20))
    company = db.Column(db.String(150)); job_role = db.Column(db.String(100))
    experience = db.Column(db.String(30)); skills = db.Column(db.Text)
    photo = db.Column(db.String(255))

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    original_name = db.Column(db.String(255))
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    department = db.Column(db.String(100))
    description = db.Column(db.Text)
    requirements = db.Column(db.Text)
    location = db.Column(db.String(150))
    active = db.Column(db.Boolean, default=True)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    job_id = db.Column(db.Integer, db.ForeignKey("job.id"), nullable=False)
    status = db.Column(db.String(30), default="Pending")
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint("user_id", "job_id", name="unique_application"),)
    candidate = db.relationship("User")
    job = db.relationship("Job")

class QRToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    revoked = db.Column(db.Boolean, default=False)

class Interview(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    application_id = db.Column(db.Integer, db.ForeignKey("application.id"), nullable=False)
    interview_at = db.Column(db.DateTime, nullable=False)
    mode = db.Column(db.String(40))
    location = db.Column(db.String(200))
    notes = db.Column(db.Text)
    status = db.Column(db.String(30), default="Scheduled")
    application = db.relationship("Application", backref="interviews")

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor = db.Column(db.String(150))
    action = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id): return db.session.get(User, int(user_id))

def role_required(role):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*args, **kwargs):
            if current_user.role != role: abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return deco

def log_action(action):
    db.session.add(AuditLog(actor=current_user.email if current_user.is_authenticated else "system", action=action))
    db.session.commit()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED

def save_upload(file, category, user_id):
    if not file or not file.filename: return None
    if not allowed_file(file.filename):
        flash("Only PDF, JPG, JPEG and PNG files are allowed.", "error"); return None
    ext=file.filename.rsplit(".",1)[1].lower()
    safe=f"{user_id}_{uuid.uuid4().hex}.{ext}"
    file.save(os.path.join(UPLOAD_DIR, safe))
    doc=Document(user_id=user_id, category=category, filename=safe, original_name=secure_filename(file.filename))
    db.session.add(doc)
    return doc

@app.context_processor
def inject_globals(): return {"now": datetime.utcnow}

@app.route("/")
def index():
    jobs=Job.query.filter_by(active=True).all()
    return render_template("index.html", jobs=jobs)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method=="POST":
        name=request.form.get("name","").strip(); email=request.form.get("email","").strip().lower()
        password=request.form.get("password","")
        if not name or not email or len(password)<8:
            flash("Enter your name/email and a password of at least 8 characters.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "error")
        else:
            user=User(name=name,email=email,password=generate_password_hash(password),role="candidate")
            db.session.add(user); db.session.flush()
            db.session.add(Profile(user_id=user.id))
            db.session.commit(); login_user(user)
            log_action("Candidate registered")
            return redirect(url_for("candidate_dashboard"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        email=request.form.get("email","").strip().lower(); password=request.form.get("password","")
        user=User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password,password):
            login_user(user); log_action("Logged in")
            return redirect(url_for("hr_dashboard" if user.role=="hr" else "candidate_dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user(); return redirect(url_for("index"))

@app.route("/candidate")
@role_required("candidate")
def candidate_dashboard():
    apps=Application.query.filter_by(user_id=current_user.id).order_by(Application.applied_at.desc()).all()
    docs=Document.query.filter_by(user_id=current_user.id).order_by(Document.uploaded_at.desc()).all()
    qr=QRToken.query.filter_by(user_id=current_user.id,revoked=False).order_by(QRToken.id.desc()).first()
    interviews=[i for a in apps for i in a.interviews]
    return render_template("candidate.html", applications=apps, docs=docs, qr=qr, interviews=interviews)

@app.route("/profile", methods=["GET","POST"])
@role_required("candidate")
def profile():
    p=current_user.profile
    if request.method=="POST":
        fields=["dob","gender","phone","street","city","state","country","pincode","college","degree","department","university","graduation_year","cgpa","company","job_role","experience","skills"]
        for field in fields: setattr(p,field,request.form.get(field,"").strip())
        photo=request.files.get("photo")
        if photo and photo.filename:
            doc=save_upload(photo,"Profile Photo",current_user.id)
            if doc: p.photo=doc.filename
        db.session.commit(); log_action("Updated candidate profile")
        flash("Profile saved.", "success"); return redirect(url_for("candidate_dashboard"))
    return render_template("profile.html", p=p)

@app.route("/documents", methods=["GET","POST"])
@role_required("candidate")
def documents():
    if request.method=="POST":
        category=request.form.get("category","Resume")
        if category not in ["Resume","10th Marksheet","12th Marksheet","Degree Certificate","Internship Certificate","Experience Letter","Technical Certificate","Other"]:
            abort(400)
        doc=save_upload(request.files.get("file"),category,current_user.id)
        if doc:
            db.session.commit(); log_action(f"Uploaded {category}")
            flash("Document uploaded.", "success")
        return redirect(url_for("documents"))
    docs=Document.query.filter_by(user_id=current_user.id).order_by(Document.uploaded_at.desc()).all()
    return render_template("documents.html", docs=docs)

@app.route("/document/<int:doc_id>")
@login_required
def document_download(doc_id):
    doc=Document.query.get_or_404(doc_id)
    if current_user.role!="hr" and doc.user_id!=current_user.id: abort(403)
    return send_from_directory(UPLOAD_DIR,doc.filename,as_attachment=True,download_name=doc.original_name)

@app.route("/document/<int:doc_id>/delete", methods=["POST"])
@role_required("candidate")
def document_delete(doc_id):
    doc=Document.query.filter_by(id=doc_id,user_id=current_user.id).first_or_404()
    try: os.remove(os.path.join(UPLOAD_DIR,doc.filename))
    except OSError: pass
    db.session.delete(doc); db.session.commit(); log_action("Deleted a document")
    flash("Document deleted.", "success"); return redirect(url_for("documents"))

@app.route("/jobs")
def jobs():
    return render_template("jobs.html", jobs=Job.query.filter_by(active=True).all())

@app.route("/apply/<int:job_id>", methods=["POST"])
@role_required("candidate")
def apply(job_id):
    job=Job.query.filter_by(id=job_id,active=True).first_or_404()
    if Application.query.filter_by(user_id=current_user.id,job_id=job.id).first():
        flash("You have already applied for this job.", "error")
    else:
        db.session.add(Application(user_id=current_user.id,job_id=job.id)); db.session.commit()
        log_action(f"Applied for job {job.title}"); flash("Application submitted.", "success")
    return redirect(url_for("candidate_dashboard"))

@app.route("/qr/generate", methods=["POST"])
@role_required("candidate")
def qr_generate():
    QRToken.query.filter_by(user_id=current_user.id,revoked=False).update({"revoked":True})
    token=secrets.token_urlsafe(32)
    record=QRToken(user_id=current_user.id,token=token,expires_at=datetime.utcnow()+timedelta(days=30))
    db.session.add(record); db.session.commit()
    verify_url=url_for("verify_qr",token=token,_external=True)
    img=qrcode.make(verify_url); filename=f"candidate_{current_user.id}.png"
    img.save(os.path.join(QR_DIR,filename))
    log_action("Generated candidate QR code")
    flash("New QR code generated. It expires in 30 days.", "success")
    return redirect(url_for("candidate_dashboard"))

@app.route("/qr/verify/<token>")
@role_required("hr")
def verify_qr(token):
    record=QRToken.query.filter_by(token=token).first()
    valid=bool(record and not record.revoked and record.expires_at>datetime.utcnow())
    candidate=db.session.get(User,record.user_id) if valid else None
    if valid: log_action(f"Verified QR for candidate ID {candidate.id}")
    else: log_action("Invalid or expired QR verification attempt")
    return render_template("verify.html", valid=valid, candidate=candidate, token_record=record)

@app.route("/hr")
@role_required("hr")
def hr_dashboard():
    return render_template("hr.html", candidates=User.query.filter_by(role="candidate").order_by(User.created_at.desc()).all(),
        applications=Application.query.order_by(Application.applied_at.desc()).all(),
        jobs=Job.query.all(), interviews=Interview.query.order_by(Interview.interview_at).all(),
        candidate_count=User.query.filter_by(role="candidate").count(),
        application_count=Application.query.count(), interview_count=Interview.query.count())

@app.route("/hr/jobs", methods=["GET","POST"])
@role_required("hr")
def hr_jobs():
    if request.method=="POST":
        job=Job(title=request.form.get("title","").strip(),department=request.form.get("department",""),
                description=request.form.get("description",""),requirements=request.form.get("requirements",""),
                location=request.form.get("location",""))
        if not job.title: flash("Job title is required.", "error")
        else:
            db.session.add(job); db.session.commit(); log_action("Created job vacancy")
            flash("Job vacancy created.", "success")
        return redirect(url_for("hr_jobs"))
    return render_template("hr_jobs.html", jobs=Job.query.all())

@app.route("/hr/jobs/<int:job_id>/toggle", methods=["POST"])
@role_required("hr")
def toggle_job(job_id):
    job=Job.query.get_or_404(job_id); job.active=not job.active
    db.session.commit(); log_action("Changed job vacancy status")
    return redirect(url_for("hr_jobs"))

@app.route("/hr/application/<int:app_id>/status", methods=["POST"])
@role_required("hr")
def application_status(app_id):
    application=Application.query.get_or_404(app_id)
    status=request.form.get("status")
    if status not in ["Pending","Shortlisted","Rejected"]: abort(400)
    application.status=status; db.session.commit(); log_action(f"Changed application {app_id} to {status}")
    flash("Application status updated.", "success")
    return redirect(request.referrer or url_for("hr_dashboard"))

@app.route("/hr/schedule/<int:app_id>", methods=["GET","POST"])
@role_required("hr")
def schedule(app_id):
    application=Application.query.get_or_404(app_id)
    if request.method=="POST":
        try: dt=datetime.strptime(request.form.get("interview_at"),"%Y-%m-%dT%H:%M")
        except (ValueError,TypeError):
            flash("Choose a valid interview date and time.", "error"); return redirect(url_for("schedule",app_id=app_id))
        if dt < datetime.now(): flash("Interview must be in the future.", "error")
        elif Interview.query.filter(Interview.interview_at==dt,Interview.status=="Scheduled").first():
            flash("That exact time is already booked. Choose another slot.", "error")
        else:
            interview=Interview(application_id=app_id,interview_at=dt,mode=request.form.get("mode","Online"),
                location=request.form.get("location",""),notes=request.form.get("notes",""))
            application.status="Shortlisted"; db.session.add(interview); db.session.commit()
            log_action(f"Scheduled interview for application {app_id}")
            flash("Interview scheduled.", "success"); return redirect(url_for("hr_dashboard"))
    return render_template("schedule.html", application=application)

@app.route("/hr/interview/<int:interview_id>/cancel", methods=["POST"])
@role_required("hr")
def cancel_interview(interview_id):
    item=Interview.query.get_or_404(interview_id); item.status="Cancelled"
    db.session.commit(); log_action(f"Cancelled interview {interview_id}")
    return redirect(url_for("hr_dashboard"))

@app.route("/hr/candidate/<int:user_id>")
@role_required("hr")
def candidate_detail(user_id):
    candidate=User.query.filter_by(id=user_id,role="candidate").first_or_404()
    docs=Document.query.filter_by(user_id=user_id).all()
    apps=Application.query.filter_by(user_id=user_id).all()
    return render_template("candidate_detail.html", candidate=candidate, docs=docs, applications=apps)

@app.route("/hr/scan")
@role_required("hr")
def scan(): return render_template("scan.html")

@app.route("/hr/audit")
@role_required("hr")
def audit(): return render_template("audit.html", logs=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(200).all())

@app.errorhandler(403)
def forbidden(e): return render_template("error.html", message="You are not authorized to view this page."),403
@app.errorhandler(404)
def not_found(e): return render_template("error.html", message="The requested page was not found."),404

def seed():
    db.create_all()
    if not User.query.filter_by(email="hr@demo.com").first():
        db.session.add(User(name="Demo HR",email="hr@demo.com",password=generate_password_hash("HRdemo@123"),role="hr"))
    if Job.query.count()==0:
        db.session.add_all([
            Job(title="Python Developer",department="Engineering",location="Chennai",description="Build and maintain Python applications.",requirements="Python, Flask, SQL, Git"),
            Job(title="Web Developer Intern",department="Technology",location="Hybrid",description="Assist with frontend and backend development.",requirements="HTML, CSS, JavaScript, Python")
        ])
    db.session.commit()

if __name__=="__main__":
    with app.app_context(): seed()
    app.run(debug=True)
