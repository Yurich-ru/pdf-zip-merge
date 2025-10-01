from fastapi import FastAPI, UploadFile, File, HTTPException, Response, Request, Form, Header
from fastapi.responses import HTMLResponse, RedirectResponse
from typing import List, Tuple
import os, re, tempfile, zipfile, secrets, base64
import httpx

# --- Настройки из окружения ---
STIRLING_BASE_URL = os.getenv("STIRLING_BASE_URL", "http://stirling-pdf:8080")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "200"))
ALLOWED_COUNT = int(os.getenv("ALLOWED_COUNT", "500"))
MAX_TOTAL_UNZIPPED_MB = int(os.getenv("MAX_TOTAL_UNZIPPED_MB", "500"))  # защита от zip-бомбы

REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() in ("1", "true", "yes")
API_KEY = os.getenv("API_KEY", "")

REQUIRE_BASIC = os.getenv("REQUIRE_BASIC", "false").lower() in ("1", "true", "yes")
BASIC_USER = os.getenv("BASIC_USER", "")
BASIC_PASS = os.getenv("BASIC_PASS", "")

APP_VERSION = os.getenv("APP_VERSION", "v0.1.x")

# --- Инициализация ---
app = FastAPI(title="PDF ZIP Merge (secured)")
name_re = re.compile(r"^(\d+)\.pdf$", re.IGNORECASE)

# --- Страницы ---
@app.get("/", include_in_schema=False)
async def root():
    # редиректим сразу на форму
    return RedirectResponse(url="/merge-zip", status_code=302)

@app.get("/merge-zip", response_class=HTMLResponse)
async def merge_zip_form():
    # Простая форма с полем X-API-Key и загрузкой ZIP
    # Поле названо x_api_key (подчёркивание), чтобы аккуратно принять его как Form-параметр;
    # По сути это то же самое поле "X-API-Key".
    return """
    <html>
      <body>
        <h3>Объединение PDF из ZIP</h3>
        <form action="/merge-zip" method="post" enctype="multipart/form-data">
          <div>
            <label>ZIP-файл (1.pdf, 2.pdf, ...):</label><br/>
            <input type="file" name="zipfile" accept=".zip" required />
          </div>
          <div style="margin-top:8px;">
            <label>X-API-Key:</label><br/>
            <input type="password" name="x_api_key" placeholder="введите API-ключ (или пришлите заголовком X-API-Key)" />
          </div>
          <div style="margin-top:12px;">
            <button type="submit">Объединить</button>
          </div>
        </form>
        <p style="margin-top:12px;font-size:12px;color:#666;">
          Версия: """ + APP_VERSION + """.
        </p>
      </body>
    </html>
    """

@app.get("/status")
async def status():
    return {"status": "ok", "version": APP_VERSION}

# --- Безопасность (ручная, без принудительного вызова BasicAuth, чтобы не триггерить браузер) ---
def check_api_key(provided: str | None):
    if REQUIRE_API_KEY:
        if not API_KEY or not provided or not secrets.compare_digest(provided, API_KEY):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

def parse_basic_auth(auth_header: str | None) -> tuple[str, str] | None:
    if not auth_header or not auth_header.startswith("Basic "):
        return None
    try:
        raw = base64.b64decode(auth_header[6:]).decode("utf-8")
        if ":" not in raw:
            return None
        user, pwd = raw.split(":", 1)
        return user, pwd
    except Exception:
        return None

def check_basic_auth(auth_header: str | None):
    if not REQUIRE_BASIC:
        return
    creds = parse_basic_auth(auth_header)
    if not (creds and BASIC_USER and BASIC_PASS):
        # Явно просим базовую авторизацию только если она включена
        raise HTTPException(status_code=401, detail="Basic auth required",
                            headers={"WWW-Authenticate": 'Basic realm="zip-merge", charset="UTF-8"'})
    user, pwd = creds
    if not (secrets.compare_digest(user, BASIC_USER) and secrets.compare_digest(pwd, BASIC_PASS)):
        raise HTTPException(status_code=401, detail="Invalid credentials",
                            headers={"WWW-Authenticate": 'Basic realm="zip-merge", charset="UTF-8"'})

# --- Утилиты ZIP ---
def zipfile_is_valid(path: str) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            bad = zf.testzip()
            return bad is None
    except:
        return False

def scan_zip(zf: zipfile.ZipFile) -> Tuple[List[Tuple[int, str]], int]:
    members = [m for m in zf.namelist() if not m.endswith("/")]
    candidates: List[Tuple[int, str]] = []
    total_unzipped = 0
    seen_numbers = set()

    for m in members:
        base = os.path.basename(m)
        m1 = name_re.match(base)
        if m1:
            num = int(m1.group(1))
            if num in seen_numbers:
                raise HTTPException(status_code=400, detail=f"Дублируется номер файла: {num}.pdf")
            seen_numbers.add(num)
            info = zf.getinfo(m)
            total_unzipped += info.file_size
            candidates.append((num, m))
    return candidates, total_unzipped

# --- Основной эндпоинт ---
@app.post("/merge-zip")
async def merge_zip(
    request: Request,
    zipfile: UploadFile = File(...),
    x_api_key_form: str | None = Form(default=None),  # поле из формы
    x_api_key_header: str | None = Header(default=None, alias="X-API-Key"),  # заголовок
):
    # 1) Проверяем Basic Auth ТОЛЬКО если она включена
    check_basic_auth(request.headers.get("authorization"))

    # 2) Проверяем API-ключ (берём из заголовка или из формы)
    provided_key = x_api_key_header or x_api_key_form
    check_api_key(provided_key)

    # 3) Проверка контента и размера запроса
    if zipfile.content_type not in ("application/zip", "application/x-zip-compressed", "application/octet-stream"):
        raise HTTPException(status_code=400, detail="Ожидался ZIP-файл")

    contents = await zipfile.read()
    size_mb = len(contents) / (1024 * 1024)
    if size_mb > MAX_UPLOAD_MB:
        raise HTTPException(status_code=413, detail=f"Слишком большой ZIP (> {MAX_UPLOAD_MB} MB)")

    tmp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    try:
        tmp_zip.write(contents); tmp_zip.flush(); tmp_zip.close()
        if not zipfile_is_valid(tmp_zip.name):
            raise HTTPException(status_code=400, detail="Некорректный ZIP")

        with zipfile.ZipFile(tmp_zip.name, "r") as zf:
            candidates, total_unzipped = scan_zip(zf)
            if not candidates:
                raise HTTPException(status_code=400, detail="В ZIP нет файлов 1.pdf, 2.pdf, ...")

            if len(candidates) > ALLOWED_COUNT:
                raise HTTPException(status_code=400, detail=f"Слишком много файлов (> {ALLOWED_COUNT})")

            total_mb = total_unzipped / (1024 * 1024)
            if total_mb > MAX_TOTAL_UNZIPPED_MB:
                raise HTTPException(status_code=413, detail=f"Суммарный объём распакованных PDF слишком большой (> {MAX_TOTAL_UNZIPPED_MB} MB)")

            candidates.sort(key=lambda x: x[0])

            with tempfile.TemporaryDirectory() as tmpdir:
                extracted_paths: List[str] = []
                for _, member in candidates:
                    target = os.path.join(tmpdir, os.path.basename(member))
                    with zf.open(member) as src, open(target, "wb") as dst:
                        dst.write(src.read())
                    extracted_paths.append(target)

                files = [("fileInput", (os.path.basename(p), open(p, "rb"), "application/pdf")) for p in extracted_paths]
                data = {"sortType": "orderProvided"}

                url = f"{STIRLING_BASE_URL}/api/v1/general/merge-pdfs"
                async with httpx.AsyncClient(timeout=120) as client:
                    r = await client.post(url, files=files, data=data)
                    for _, f in files:
                        f[1].close()
                    if r.status_code != 200 or r.headers.get("content-type", "").split(";")[0] != "application/pdf":
                        raise HTTPException(status_code=502, detail=f"Stirling-PDF вернул ошибку {r.status_code}: {r.text[:300]}")
                    pdf_bytes = r.content

                resp = Response(
                    content=pdf_bytes,
                    media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="merged.pdf"'},
                )
                # Доп. security-заголовки
                resp.headers["X-Content-Type-Options"] = "nosniff"
                resp.headers["X-Frame-Options"] = "DENY"
                resp.headers["Referrer-Policy"] = "no-referrer"
                resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
                return resp
    finally:
        try: os.unlink(tmp_zip.name)
        except: pass
