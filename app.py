"""رد تلقائي على تعليقات فيسبوك وإنستغرام مع لوحة تحكم."""
import hashlib, hmac, os, re, secrets, sqlite3, time
from functools import wraps

import requests
from flask import Flask, redirect, render_template_string, request, session

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(16)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
DB = os.path.join(os.environ.get("DATA_DIR", "."), "data.db")
GRAPH = "https://graph.facebook.com/v21.0"
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    return c


with db() as c:
    c.executescript(
        """create table if not exists settings(k text primary key, v text);
        create table if not exists rules(id integer primary key, keywords text, reply text);
        create table if not exists logs(id integer primary key, ts integer,
            platform text, comment text, reply text, status text);"""
    )


def get(k, default=""):
    with db() as c:
        r = c.execute("select v from settings where k=?", (k,)).fetchone()
    if r and r["v"] != "":
        return r["v"]
    return os.environ.get(k.upper(), default)


def put(k, v):
    with db() as c:
        c.execute(
            "insert into settings values(?,?) on conflict(k) do update set v=excluded.v",
            (k, v),
        )


def verify_token():
    t = get("verify_token")
    if not t:
        t = secrets.token_urlsafe(12)
        put("verify_token", t)
    return t


def pick_reply(text):
    text = (text or "").lower()
    with db() as c:
        rules = c.execute("select keywords, reply from rules order by id").fetchall()
    for r in rules:
        words = [w.strip().lower() for w in re.split(r"[,،]", r["keywords"]) if w.strip()]
        if any(w in text for w in words):
            return r["reply"]
    return get("default_reply", "شكراً لتعليقك! 🌹")


def log(platform, comment, reply, status):
    with db() as c:
        c.execute(
            "insert into logs(ts,platform,comment,reply,status) values(?,?,?,?,?)",
            (int(time.time()), platform, (comment or "")[:300], reply, status),
        )
        c.execute("delete from logs where id not in (select id from logs order by id desc limit 200)")


def send(platform, comment_id, text, original):
    path = "comments" if platform == "facebook" else "replies"
    try:
        r = requests.post(
            f"{GRAPH}/{comment_id}/{path}",
            data={"message": text, "access_token": get("page_token")},
            timeout=15,
        )
        log(platform, original, text, "تم" if r.ok else f"فشل: {r.text[:120]}")
    except requests.RequestException as e:
        log(platform, original, text, f"فشل: {e}")


# ---------- Webhook ----------
@app.get("/webhook")
def verify():
    if request.args.get("hub.mode") == "subscribe" and hmac.compare_digest(
        request.args.get("hub.verify_token", ""), verify_token()
    ):
        return request.args.get("hub.challenge", ""), 200
    return "forbidden", 403


@app.post("/webhook")
def webhook():
    secret = get("app_secret")
    if secret:
        expected = "sha256=" + hmac.new(secret.encode(), request.get_data(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(request.headers.get("X-Hub-Signature-256", ""), expected):
            return "bad signature", 403
    if get("enabled", "1") != "1":
        return "paused", 200
    data = request.get_json(silent=True) or {}
    for entry in data.get("entries", []) or data.get("entry", []):
        for ch in entry.get("changes", []):
            v = ch.get("value", {})
            if data.get("object") == "page" and ch.get("field") == "feed" \
                    and v.get("item") == "comment" and v.get("verb") == "add":
                if v.get("from", {}).get("id") != get("page_id"):
                    send("facebook", v["comment_id"], pick_reply(v.get("message")), v.get("message"))
            elif data.get("object") == "instagram" and ch.get("field") == "comments":
                if v.get("from", {}).get("id") != get("ig_user_id") and not v.get("parent_id"):
                    send("instagram", v["id"], pick_reply(v.get("text")), v.get("text"))
    return "ok", 200


# ---------- Dashboard ----------
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not session.get("ok"):
            return redirect("/login")
        return f(*a, **k)
    return w


CSS = """
:root{--bg:#f5f7f6;--fg:#16231f;--mut:#5d6d67;--line:#d5ddd9;--ac:#0b6b57;--acfg:#fff;--in:#fff;--bad:#b3261e}
@media(prefers-color-scheme:dark){:root{--bg:#101815;--fg:#e6efeb;--mut:#93a49d;--line:#27352f;--ac:#3fb89c;--acfg:#06201a;--in:#17221e;--bad:#ff8a80}}
*{box-sizing:border-box}html{font-family:'IBM Plex Sans Arabic',Tahoma,sans-serif}
body{margin:0;background:var(--bg);color:var(--fg);line-height:1.7;
 padding:max(16px,env(safe-area-inset-top)) 16px max(24px,env(safe-area-inset-bottom))}
main{max-width:620px;margin:0 auto}
h1{font-size:1.5rem;margin:.5rem 0 .2rem}h2{font-size:1.05rem;margin:0 0 .6rem}
section{border-top:1px solid var(--line);padding:1.2rem 0}
p,small{color:var(--mut);margin:.2rem 0 .8rem}
label{display:block;font-size:.9rem;margin:.7rem 0 .2rem}
input,textarea{width:100%;font:inherit;color:var(--fg);background:var(--in);
 border:1px solid var(--line);border-radius:8px;padding:.6rem .7rem}
input:focus,textarea:focus,button:focus-visible,a:focus-visible{outline:2px solid var(--ac);outline-offset:2px}
button{font:inherit;background:var(--ac);color:var(--acfg);border:0;border-radius:8px;
 padding:.6rem 1.1rem;margin-top:.8rem;cursor:pointer}
button.ghost{background:none;color:var(--bad);padding:.2rem .4rem;margin:0}
.row{display:flex;justify-content:space-between;gap:.8rem;align-items:flex-start;
 padding:.6rem 0;border-bottom:1px solid var(--line)}
code{direction:ltr;display:block;background:var(--in);border:1px solid var(--line);
 border-radius:8px;padding:.5rem .7rem;overflow-x:auto;font-size:.85rem;margin-bottom:.5rem}
.ok{color:var(--ac)}.err{color:var(--bad)}.top{display:flex;justify-content:space-between;align-items:center}
.top a{color:var(--mut);font-size:.9rem}
"""
FONT = '<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans+Arabic:wght@400;600&display=swap" rel="stylesheet">'
HEAD = f'<!doctype html><html lang="ar" dir="rtl"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"><title>الرد التلقائي</title>{FONT}<style>{CSS}</style>'

LOGIN = HEAD + """<main><h1>تسجيل الدخول</h1>
{% if not has_pw %}<p class="err">لم تُضبط كلمة المرور. أضف المتغير ADMIN_PASSWORD في إعدادات الاستضافة ثم أعد التشغيل.</p>
{% else %}<form method="post"><label>كلمة المرور</label><input type="password" name="pw" required autofocus>
{% if bad %}<p class="err">كلمة المرور غير صحيحة.</p>{% endif %}<button>دخول</button></form>{% endif %}</main>"""

HOME = HEAD + """<main>
<div class="top"><h1>الرد التلقائي</h1><a href="/logout">خروج</a></div>
<p class="{{ 'ok' if ready else 'err' }}">{{ 'شغّال: يرد على التعليقات الجديدة.' if ready else status_msg }}</p>

<section><h2>رابط الربط مع Meta</h2>
<p>الصق هذين في إعدادات Webhooks في تطبيق Meta.</p>
<code>{{ url }}webhook</code><code>{{ vt }}</code></section>

<section><h2>الردود حسب الكلمات</h2>
{% for r in rules %}<div class="row"><div><b>{{ r.keywords }}</b><br><small>{{ r.reply }}</small></div>
<form method="post" action="/rule/del/{{ r.id }}"><button class="ghost">حذف</button></form></div>
{% else %}<p>ما أضفت أي رد بعد. كل التعليقات تأخذ الرد الافتراضي.</p>{% endfor %}
<form method="post" action="/rule/add">
<label>الكلمات (افصل بينها بفاصلة)</label><input name="keywords" placeholder="سعر، بكم، كم" required>
<label>الرد</label><textarea name="reply" rows="2" required></textarea><button>إضافة رد</button></form></section>

<section><h2>الإعدادات</h2>
<form method="post" action="/save">
<label>الرد الافتراضي</label><textarea name="default_reply" rows="2">{{ s.default_reply }}</textarea>
<label>Page Access Token</label><input name="page_token" type="password" placeholder="{{ 'محفوظ، اتركه فارغاً للإبقاء عليه' if s.page_token else '' }}">
<label>معرّف صفحة فيسبوك (Page ID)</label><input name="page_id" value="{{ s.page_id }}" inputmode="numeric">
<label>معرّف حساب إنستغرام (IG User ID)</label><input name="ig_user_id" value="{{ s.ig_user_id }}" inputmode="numeric">
<label>App Secret (اختياري)</label><input name="app_secret" type="password" placeholder="{{ 'محفوظ' if s.app_secret else '' }}">
<label><input type="checkbox" name="enabled" value="1" style="width:auto" {{ 'checked' if s.enabled == '1' }}> تفعيل الرد التلقائي</label>
<button>حفظ الإعدادات</button></form></section>

<section><h2>آخر الردود</h2>
{% for l in logs %}<div class="row"><div><small>{{ l.platform }} · {{ l.when }}</small><br>{{ l.comment }}<br>
<small>← {{ l.reply }}</small></div><span class="{{ 'ok' if l.status == 'تم' else 'err' }}">{{ l.status[:40] }}</span></div>
{% else %}<p>ما وصل أي تعليق بعد.</p>{% endfor %}</section></main>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    bad = False
    if request.method == "POST" and ADMIN_PASSWORD:
        if hmac.compare_digest(request.form.get("pw", ""), ADMIN_PASSWORD):
            session["ok"] = True
            return redirect("/")
        bad = True
    return render_template_string(LOGIN, has_pw=bool(ADMIN_PASSWORD), bad=bad)


@app.get("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.get("/")
@login_required
def home():
    s = {k: get(k) for k in ["default_reply", "page_token", "page_id", "ig_user_id", "app_secret"]}
    s["default_reply"] = s["default_reply"] or "شكراً لتعليقك! 🌹"
    s["enabled"] = get("enabled", "1")
    ready = bool(s["page_token"] and (s["page_id"] or s["ig_user_id"]) and s["enabled"] == "1")
    msg = "متوقف." if s["enabled"] != "1" else "ناقص: أضف Page Access Token ومعرّف الصفحة في الإعدادات."
    with db() as c:
        rules = c.execute("select * from rules order by id").fetchall()
        logs = [dict(r) for r in c.execute("select * from logs order by id desc limit 30")]
    for l in logs:
        l["when"] = time.strftime("%Y-%m-%d %H:%M", time.gmtime(l["ts"])) + " UTC"
    return render_template_string(
        HOME, s=s, ready=ready, status_msg=msg, rules=rules, logs=logs,
        url=request.url_root.replace("http://", "https://"), vt=verify_token(),
    )


@app.post("/save")
@login_required
def save():
    for k in ["default_reply", "page_id", "ig_user_id"]:
        put(k, request.form.get(k, "").strip())
    for k in ["page_token", "app_secret"]:  # الفارغ = إبقاء القيمة القديمة
        if request.form.get(k, "").strip():
            put(k, request.form[k].strip())
    put("enabled", "1" if request.form.get("enabled") else "0")
    return redirect("/")


@app.post("/rule/add")
@login_required
def rule_add():
    with db() as c:
        c.execute("insert into rules(keywords,reply) values(?,?)",
                  (request.form["keywords"].strip(), request.form["reply"].strip()))
    return redirect("/")


@app.post("/rule/del/<int:rid>")
@login_required
def rule_del(rid):
    with db() as c:
        c.execute("delete from rules where id=?", (rid,))
    return redirect("/")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
