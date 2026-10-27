import os
import hashlib
import uuid
import json
from datetime import datetime

from flask import (
    Flask, render_template, request, redirect,
    url_for, flash, send_file
)
from werkzeug.utils import secure_filename

from models import db, Evidence

app = Flask(__name__)
app.config['SECRET_KEY'] = 'cybershield-demo-key-change-me'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybershield.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024  # 200 MB

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
REPORTS_FOLDER = os.path.join(BASE_DIR, 'reports')

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['REPORTS_FOLDER'] = REPORTS_FOLDER

db.init_app(app)


def compute_hashes(filepath):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def save_upload(file_storage, module_name):
    original = secure_filename(file_storage.filename)
    if not original:
        raise ValueError("Invalid filename")
    ext = original.rsplit('.', 1)[-1].lower() if '.' in original else ''
    stored = f"{uuid.uuid4().hex}.{ext}" if ext else uuid.uuid4().hex
    path = os.path.join(app.config['UPLOAD_FOLDER'], stored)
    file_storage.save(path)
    md5, sha256 = compute_hashes(path)
    ev = Evidence(
        evidence_id=f"EV-{uuid.uuid4().hex[:8].upper()}",
        original_filename=original,
        stored_filename=stored,
        file_size=os.path.getsize(path),
        md5=md5,
        sha256=sha256,
        module=module_name,
        status="uploaded"
    )
    return ev, path


def analyze_module(module_name, filepath, ev):
    base = {
        "evidence_id": ev.evidence_id,
        "filename": ev.original_filename,
        "size_bytes": ev.file_size,
        "md5": ev.md5,
        "sha256": ev.sha256,
        "limitations": []
    }

    if module_name == 'file':
        base['summary'] = "File metadata and hashes extracted successfully."
        base['details'] = {
            "extension": (
                ev.original_filename.rsplit('.', 1)[-1]
                if '.' in ev.original_filename else "none"
            ),
            "size_human": (
                f"{ev.file_size / 1024:.1f} KB"
                if ev.file_size > 1024 else f"{ev.file_size} B"
            )
        }

    elif module_name == 'network':
        try:
            from scapy.all import rdpcap, IP, TCP, UDP
            packets = rdpcap(filepath)
            ips, protocols = set(), set()
            for pkt in packets[:1000]:
                if IP in pkt:
                    ips.add(pkt[IP].src)
                    ips.add(pkt[IP].dst)
                if TCP in pkt:
                    protocols.add("TCP")
                elif UDP in pkt:
                    protocols.add("UDP")
            base['summary'] = f"Parsed {len(packets)} packets from PCAP."
            base['details'] = {
                "packet_count": len(packets),
                "unique_ip_count": len(ips),
                "protocols_seen": list(protocols),
                "sample_ips": list(ips)[:10]
            }
        except ImportError:
            base['summary'] = "Scapy not installed. Run: pip install scapy"
            base['details'] = {}
            base['limitations'].append("Install scapy for PCAP parsing.")
        except Exception as e:
            base['summary'] = f"Could not parse as PCAP: {e}"
            base['details'] = {}
            base['limitations'].append("File may not be a valid PCAP/PCAPNG.")

    elif module_name == 'memory':
        base['summary'] = "Memory dump hashed. Volatility 3 required for deep analysis."
        base['details'] = {"sha256": ev.sha256, "size_bytes": ev.file_size}
        base['limitations'].append(
            "Full memory forensics needs Volatility 3: pip install volatility3"
        )

    elif module_name == 'malware':
        base['summary'] = "Static analysis complete (file was NEVER executed)."
        details = {
            "md5": ev.md5,
            "sha256": ev.sha256,
            "size": ev.file_size
        }
        try:
            with open(filepath, 'rb') as f:
                data = f.read(1024 * 1024)
            printable = ''.join(chr(b) if 32 <= b < 127 else ' ' for b in data)
            suspicious = [
                s for s in
                ['http://', 'https://', 'cmd.exe', 'powershell',
                 'VirtualAlloc', 'CreateRemoteThread', '.exe', '.dll']
                if s in printable
            ]
            details['suspicious_strings_found'] = suspicious
            base['limitations'].append("String scan limited to first 1 MB.")
        except Exception:
            pass
        base['details'] = details
        base['limitations'].append(
            "YARA scanning not available (install yara-python to enable)."
        )

    elif module_name == 'timeline':
        stat = os.stat(filepath)
        base['summary'] = "File timestamps extracted."
        base['details'] = {
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat()
        }

    else:
        base['summary'] = f"{module_name.capitalize()} module: file accepted and hashed."
        base['details'] = {"sha256": ev.sha256}
        base['limitations'].append(
            f"Deep {module_name} analysis requires external tools "
            "(e.g., Sleuth Kit, Volatility, Cellebrite). "
            "This demo verifies the file's integrity only."
        )

    return base


VALID_MODULES = {
    'disk', 'memory', 'file', 'network', 'mobile',
    'timeline', 'recovery', 'malware', 'cloud'
}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/module/<module_name>', methods=['GET', 'POST'])
def module_handler(module_name):
    if module_name not in VALID_MODULES:
        flash('Unknown module', 'error')
        return redirect(url_for('index'))

    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        try:
            ev, filepath = save_upload(file, module_name)
            db.session.add(ev)
            db.session.commit()
            result = analyze_module(module_name, filepath, ev)
            ev.analysis_result = json.dumps(result)
            ev.status = "analyzed"
            db.session.commit()
            return render_template(
                'index.html',
                result=result, evidence=ev, module=module_name
            )
        except Exception as e:
            db.session.rollback()
            flash(f'Analysis error: {e}', 'error')
            return redirect(request.url)

    return render_template('index.html', module=module_name)


@app.route('/evidence')
def evidence_list():
    items = Evidence.query.order_by(Evidence.created_at.desc()).all()
    return render_template('index.html', evidence_list=items)


@app.route('/report/<int:evidence_pk>')
def download_report(evidence_pk):
    ev = Evidence.query.get_or_404(evidence_pk)
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    pdf_path = os.path.join(
        app.config['REPORTS_FOLDER'],
        f"report_{ev.evidence_id}.pdf"
    )
    c = canvas.Canvas(pdf_path, pagesize=letter)
    y = 750
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "CyberShield Forensic Report")
    y -= 30
    c.setFont("Helvetica", 11)
    lines = [
        f"Evidence ID: {ev.evidence_id}",
        f"File: {ev.original_filename}",
        f"Size: {ev.file_size} bytes",
        f"MD5: {ev.md5}",
        f"SHA256: {ev.sha256}",
        f"Module: {ev.module}",
        f"Status: {ev.status}",
        f"Created: {ev.created_at.isoformat()}",
        "--- Analysis Result ---",
    ]
    if ev.analysis_result:
        try:
            data = json.loads(ev.analysis_result)
            lines.append(f"Summary: {data.get('summary', '')}")
            for k, v in data.get('details', {}).items():
                lines.append(f"  {k}: {v}")
            for lim in data.get('limitations', []):
                lines.append(f"LIMITATION: {lim}")
        except Exception:
            lines.append(ev.analysis_result[:2000])
    for line in lines:
        if y < 50:
            c.showPage()
            y = 750
            c.setFont("Helvetica", 11)
        c.drawString(50, y, str(line))
        y -= 16
    c.save()
    return send_file(
        pdf_path, as_attachment=True,
        download_name=f"cybershield_{ev.evidence_id}.pdf"
    )


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='127.0.0.1', port=5000, debug=True)
