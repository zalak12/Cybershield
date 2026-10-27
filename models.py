from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Evidence(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    evidence_id = db.Column(db.String(64), unique=True, nullable=False)
    original_filename = db.Column(db.String(256), nullable=False)
    stored_filename = db.Column(db.String(256), nullable=False)
    file_size = db.Column(db.Integer, default=0)
    md5 = db.Column(db.String(32))
    sha256 = db.Column(db.String(64))
    module = db.Column(db.String(64))
    status = db.Column(db.String(32), default="pending")
    analysis_result = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
