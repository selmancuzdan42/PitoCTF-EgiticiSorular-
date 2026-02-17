from flask import Flask, request, jsonify, render_template_string
import threading

app = Flask(__name__)
pending = {}
lock = threading.Lock()

MOBILE_HTML = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Pardus Akıllı Kumanda</title>
    <style>
        body { font-family: sans-serif; margin: 0; background: #1e1e2e; height: 100vh; display: flex; flex-direction: column; color: white; }
        .header { padding: 20px; text-align: center; background: rgba(255,255,255,0.05); }
        .status { font-size: 12px; color: #a6adc8; margin-top: 5px; }
        .controls { flex: 1; display: flex; flex-direction: column; justify-content: center; align-items: center; gap: 15px; padding: 20px; }
        .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; width: 100%; max-width: 300px; }
        .btn { border: none; color: #1e1e2e; padding: 25px; font-size: 16px; font-weight: bold; cursor: pointer; border-radius: 15px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); display: flex; flex-direction: column; align-items: center; justify-content: center; }
        .btn:active { transform: scale(0.96); }
        .btn-unlock { background: #a6e3a1; grid-column: span 2; }
        .btn-lock   { background: #f38ba8; grid-column: span 2; }
        .btn-prev   { background: #89b4fa; }
        .btn-next   { background: #89b4fa; }
        .hidden { display: none !important; }
    </style>
</head>
<body>
    <div class="header">
        <div>PARDUS PİLOT</div>
        <div id="status" class="status">Bağlı</div>
    </div>
    <div class="controls">
        <div id="unlockPanel" class="grid">
            <button class="btn btn-unlock" onclick="cmd('unlock')">🔓 KİLİDİ AÇ</button>
        </div>
        <div id="remotePanel" class="grid hidden">
            <button class="btn btn-lock" onclick="cmd('lock')">🔒 KİLİTLE</button>
            <button class="btn btn-prev" onclick="cmd('prev')">⬅️ GERİ</button>
            <button class="btn btn-next" onclick="cmd('next')">➡️ İLERİ</button>
        </div>
    </div>
    <script>
        function cmd(c) {
            document.getElementById('status').innerText = "Gönderiliyor...";
            fetch('/api/control?token={{ token }}&command=' + c, { method: 'POST' })
                .then(r => r.json()).then(d => {
                    document.getElementById('status').innerText = d.success ? "Başarılı ✅" : "Hata ❌";
                    if(c === 'unlock') {
                        document.getElementById('unlockPanel').classList.add('hidden');
                        document.getElementById('remotePanel').classList.remove('hidden');
                    }
                    if(c === 'lock') {
                        document.getElementById('unlockPanel').classList.remove('hidden');
                        document.getElementById('remotePanel').classList.add('hidden');
                    }
                }).catch(() => { document.getElementById('status').innerText = "Bağlantı Hatası ❌"; });
        }
    </script>
</body>
</html>
"""

@app.route('/register', methods=['POST'])
def register():
    token = request.args.get('token')
    with lock:
        pending[token] = []
    return jsonify({"success": True})

@app.route('/controller')
def controller():
    token = request.args.get('token')
    if token not in pending:
        return "Geçersiz token", 403
    return render_template_string(MOBILE_HTML, token=token)

@app.route('/api/control', methods=['POST'])
def control():
    token = request.args.get('token')
    command = request.args.get('command')
    with lock:
        if token in pending:
            pending[token].append(command)
            return jsonify({"success": True})
    return jsonify({"success": False, "message": "Token bulunamadı"}), 404

@app.route('/poll')
def poll():
    token = request.args.get('token')
    with lock:
        if token in pending and pending[token]:
            return jsonify({"command": pending[token].pop(0)})
    return jsonify({"command": None})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
