#!/usr/bin/env python3
# Web Maker Mailer: ওটিপি কোড + পেমেন্ট সফল/অসফল ইমেইল
import os, re, time, ssl, smtplib, secrets, hashlib, hmac, html, logging
import http.server, socketserver, threading
from email.message import EmailMessage
from email.utils import formataddr
import firebase_admin
from firebase_admin import credentials, db, auth

logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)
log = logging.getLogger("wm-mailer")

DB_URL    = os.environ.get("DB_URL", "https://bd-web-maker-default-rtdb.firebaseio.com")
CRED_FILE = os.environ.get("FIREBASE_CRED", "serviceAccount.json")
MAIL_USER = os.environ["MAIL_USER"]
MAIL_PASS = os.environ["MAIL_PASS"].replace(" ", "")
MAIL_NAME = os.environ.get("MAIL_NAME", "Web Maker")
PAY_BOT   = os.environ.get("PAY_BOT", "PaymentVerifyBdWebMakerBot")
WORK_BOT  = os.environ.get("WORK_BOT", "WebMakerBdBot")

OTP_TTL, MAX_TRIES, HOURLY_CAP = 600, 5, 5
PKG = {"basic": "নরমাল", "plus": "প্লাস", "pro": "প্রো", "standard": "মাঝারি", "ultra": "হাই-টেক"}
esc = html.escape
def now_ms(): return int(time.time() * 1000)
def ref(p): return db.reference(p)

# ---------- Render Free Web Service Port Handler ----------
def run_dummy_server():
    port = int(os.environ.get("PORT", 8080))
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        httpd.serve_forever()

# ---------- ইমেইল পাঠানো ----------
def send_mail(to, subject, text, body_html):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = formataddr((MAIL_NAME, MAIL_USER))
    msg["To"] = to
    msg.set_content(text)
    msg.add_alternative(body_html, subtype="html")
    last = None
    for _ in range(2):
        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=ssl.create_default_context(), timeout=30) as s:
                s.login(MAIL_USER, MAIL_PASS)
                s.send_message(msg)
            return
        except Exception as e:
            last = e; time.sleep(2)
    raise last

def wrap(title, color, inner):
    return (f'<div style="background:#0b0f19;padding:24px;font-family:Arial,sans-serif">'
            f'<div style="max-width:520px;margin:auto;background:#121724;border:1px solid #2a3142;border-radius:14px;padding:24px;color:#f0f6fc">'
            f'<h2 style="margin:0 0 14px;color:{color}">{title}</h2>{inner}'
            f'<hr style="border:none;border-top:1px solid #2a3142;margin:18px 0">'
            f'<p style="color:#8b949e;font-size:12px;margin:0">{esc(MAIL_NAME)} — এটি স্বয়ংক্রিয় ইমেইল, উত্তর দেওয়ার দরকার নেই।</p></div></div>')

# ---------- ১) ওটিপি অনুরোধ ----------
def handle_requests():
    for uid in list((ref("otpReq").get() or {}).keys()):
        try:
            ref(f"otpReq/{uid}").delete()
            st = ref(f"otpState/{uid}").get() or {}
            sent = [t for t in st.get("sent", []) if t > now_ms() - 3600_000]
            if len(sent) >= HOURLY_CAP:
                log.warning("hourly cap reached uid=%s", uid); continue
            email = auth.get_user(uid).email
            if not email: continue
            code = f"{secrets.randbelow(10**6):06d}"
            salt = secrets.token_hex(8)
            ref(f"otpState/{uid}").set({
                "h": hashlib.sha256((salt + code).encode()).hexdigest(), "salt": salt,
                "exp": now_ms() + OTP_TTL * 1000, "tries": 0, "sent": sent + [now_ms()]})
            inner = (f'<p>আপনার যাচাই কোড:</p>'
                     f'<p style="font-size:34px;letter-spacing:10px;font-weight:bold;color:#00f2fe;margin:10px 0">{code}</p>'
                     f'<p style="color:#8b949e">কোডটি {OTP_TTL // 60} মিনিট পর্যন্ত চলবে। এটি কাউকে দেবেন না। আপনি অনুরোধ না করে থাকলে এই ইমেইল উপেক্ষা করুন।</p>')
            send_mail(email, f"আপনার যাচাই কোড: {code}", f"আপনার Web Maker যাচাই কোড: {code} ({OTP_TTL // 60} মিনিট চলবে)", wrap("ইমেইল যাচাই", "#00f2fe", inner))
            log.info("otp sent uid=%s", uid)
        except Exception as e:
            log.error("otp request failed uid=%s: %s", uid, e)

# ---------- ২) ওটিপি যাচাই ----------
def handle_tries():
    for uid, t in list((ref("otpTry").get() or {}).items()):
        try:
            ref(f"otpTry/{uid}").delete()
            t = t if isinstance(t, dict) else {}
            n = str(t.get("n", ""))[:20]
            code = str(t.get("code", ""))
            def res(ok, msg): ref(f"otpResult/{uid}").set({"n": n, "ok": ok, "msg": msg, "at": now_ms()})
            st = ref(f"otpState/{uid}").get() or {}
            if not st.get("h") or st.get("exp", 0) < now_ms():
                res(False, "expired"); continue
            if st.get("tries", 0) >= MAX_TRIES:
                ref(f"otpState/{uid}").set({"sent": st.get("sent", [])}); res(False, "locked"); continue
            ok = re.fullmatch(r"\d{6}", code) is not None and hmac.compare_digest(
                hashlib.sha256((st["salt"] + code).encode()).hexdigest(), st["h"])
            if ok:
                ref(f"verified/{uid}").set({"ok": True, "at": now_ms()})
                ref(f"otpState/{uid}").set({"sent": st.get("sent", [])})
                res(True, "ok")
            else:
                ref(f"otpState/{uid}/tries").set(st.get("tries", 0) + 1)
                res(False, "wrong")
        except Exception as e:
            log.error("otp check failed uid=%s: %s", uid, e)

# ---------- ৩) পেমেন্ট সফল / অসফল ইমেইল ----------
fail_count, fail_until = {}, {}
def mask(s):
    s = str(s or ""); return s[:3] + "•••" + s[-2:] if len(s) > 5 else "•••"

def handle_status():
    review = ref("review").get() or {}
    mstate = ref("mailState").get() or {}
    for oid, r in review.items():
        st = (r or {}).get("status")
        if st == "pending":
            if oid in mstate: ref(f"mailState/{oid}").delete()
            continue
        if st not in ("approved", "rejected") or mstate.get(oid) == st: continue
        if fail_until.get(oid, 0) > time.time(): continue
        try:
            o = ref(f"orders/{oid}").get()
            if not o or not o.get("email"):
                ref(f"mailState/{oid}").set(st); continue
            pk = PKG.get(o.get("package"), str(o.get("package")))
            rows = (f'<p style="line-height:1.9;margin:0">অর্ডার আইডি: <b>{esc(oid)}</b><br>'
                    f'প্যাকেজ: <b>{esc(pk)} (৳{esc(str(o.get("price")))})</b><br>'
                    f'পেমেন্ট: <b>{"bKash" if o.get("method") == "bkash" else "Nagad"}</b><br>'
                    f'TrxID: <b>{esc(mask(o.get("trx")))}</b></p>')
            if st == "approved":
                subject = f"✅ পেমেন্ট সফল হয়েছে – অর্ডার {oid} কনফার্ম"
                inner = (f'<p>আপনার পেমেন্ট সফলভাবে যাচাই হয়েছে এবং অর্ডার কনফার্ম হয়েছে।</p>{rows}'
                         f'<p style="margin-top:14px">ওয়েবসাইটের লিংক ও কাজের বিস্তারিত নিয়ে কথা বলতে টেলিগ্রামে <b>@{esc(WORK_BOT)}</b> এ যান:<br>'
                         f'<a href="https://t.me/{esc(WORK_BOT)}?start={esc(oid)}" style="color:#00f2fe">https://t.me/{esc(WORK_BOT)}</a></p>')
                text = f"পেমেন্ট সফল! অর্ডার {oid} কনফার্ম হয়েছে। টেলিগ্রামে @{WORK_BOT} এ যান।"
                body = wrap("✅ পেমেন্ট সফল হয়েছে", "#2ea44f", inner)
            else:
                subject = f"❌ পেমেন্ট যাচাই সফল হয়নি – অর্ডার {oid}"
                inner = (f'<p>দুঃখিত, আপনার পেমেন্ট যাচাই করা যায়নি (TrxID বা টাকার পরিমাণ মেলেনি) অথবা অর্ডার বাতিল হয়েছে।</p>{rows}'
                         f'<p style="margin-top:14px">আপনি সত্যিই পেমেন্ট করে থাকলে টেলিগ্রামে <b>@{esc(PAY_BOT)}</b> এ গিয়ে ইমেইল, অর্ডার আইডি ও TrxID দিয়ে যাচাই করুন:<br>'
                         f'<a href="https://t.me/{esc(PAY_BOT)}?start={esc(oid)}" style="color:#00f2fe">https://t.me/{esc(PAY_BOT)}</a><br>'
                         f'সব ঠিক থাকলে সেখান থেকে সরাসরি অ্যাডমিনের সাথে কথা বলতে পারবেন।</p>')
                text = f"পেমেন্ট যাচাই সফল হয়নি। অর্ডার {oid}। সাহায্যের জন্য টেলিগ্রামে @{PAY_BOT} এ যান।"
                body = wrap("❌ পেমেন্ট যাচাই সফল হয়নি", "#ff5c5c", inner)
            send_mail(o["email"], subject, text, body)
            ref(f"mailState/{oid}").set(st)
            log.info("status mail sent %s -> %s", oid, st)
        except Exception as e:
            fail_count[oid] = fail_count.get(oid, 0) + 1
            if fail_count[oid] >= 3: fail_until[oid] = time.time() + 600; fail_count[oid] = 0
            log.error("status mail failed %s: %s", oid, e)

def main():
    firebase_admin.initialize_app(credentials.Certificate(CRED_FILE), {"databaseURL": DB_URL})
    log.info("Mailer started")
    last = 0
    while True:
        try:
            handle_requests(); handle_tries()
            if time.time() - last >= 10:
                handle_status(); last = time.time()
        except Exception as e:
            log.error("loop error: %s", e)
        time.sleep(2)

if __name__ == "__main__":
    threading.Thread(target=run_dummy_server, daemon=True).start()
    main()
