from fastapi import FastAPI, UploadFile, File, HTTPException, Response, Depends
from fastapi.responses import HTMLResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from typing import List, Tuple
import os, re, tempfile, zipfile, secrets
import httpx

# --- Настройки из окружения --- 
STIRLING_BASE_URL = os.getenv("STIRLING_BASE_URL", "http://stirling-pdf:8080")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "200"))
ALLOWED_COUNT = int(os.getenv("ALLOWED_COUNT", "500"))
MAX_TOTAL_UNZIPPED_MB = int(os.getenv("MAX_TOTAL_UNZIPPED_MB", "500"))  # защита от zip-бомбы
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() in ("1","true","yes")
API_KEY = os.getenv("API_KEY", "")  # если пусто и REQUIRE_API_KEY=true — будет 401
REQUIRE_BASIC = os.getenv("REQUIRE_BASIC", "false").lower() in ("1","true","yes")
BASIC_USER = os.getenv("BASIC_USER", "")
BASIC_PASS = os.getenv("BASIC_PASS", "")

# --- Инициализация ---
app = FastAPI(title="PDF ZIP Merge (secured)")
security = HTTPBasic()
name_re = re.compile(r"^(\d+)\.pdf$", re.IGNORECASE)

# --- Простая страница и статус ---
@app.get("/", response_class=HTMLResponse)
async def index():
    return """
    <html><body>
    <h3>Загрузите ZIP (1.pdf, 2.pdf, ...)</h3>
    <form action="/merge-zip" method="post" enctype="multipart/form-data">
      <input type="file" name="zipfile" accept=".zip" />
      <button type="submit">Объединить</button>
    </form>
    </body></html>
    """

@app.get("/status")
async def status():
    return {"status": "ok"}

# --- Безопасность: API key и/или BasicAuth ---
def check_api_key(x_api_key: str | None) -> None:
    if REQUIRE_API_KEY:
        if not API_KEY or not x_api_key or not secrets.compare_digest(x_api_key, API_KEY):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")

def check_basic(creds: HTTPBasicCredentials | None) -> None:
    if REQUIRE_BASIC:
        if not (BASIC_USER and BASIC_PASS and creds):
            raise HTTPException(status_code=401, detail="Basic auth required")
        if not (secrets.compare_digest(creds.username, BASIC_USER) and secrets.compare_digest(creds.password, BASIC_PASS)):
            raise HTTPException(status_code=401, detail="Invalid credentials")

async def guard(x_api_key: str | None = None, creds: HTTPBasicCredentials = Depends(security)):
    # Проверяем оба фактора по настройкам
    if REQUIRE_API_KEY:
        check_api_key(x_api_key)
    if REQUIRE_BASIC:
        check_basic(creds)

# --- Утилиты для ZIP-защиты ---
def zipfile_is_valid(path: str) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            bad = zf.testzip()
            return bad is None
    except:
        return False

def scan_zip(zf: zipfile.ZipFile) -> Tuple[List[Tuple[int, str]], int]:
    """
    Возвращает: (список (номер, путь_в_архиве) только для N.pdf, сумма распакованных байт)
    """
    members = [m for m in zf.namelist() if not m.endswith("/")]
    candidates: List[Tuple[int,str]] = []
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
@app.post("/merge-zip", dependencies=[Depends(guard)])
async def merge_zip(zipfile: UploadFile = File(...), x_api_key: str | None = None):
    # Проверка контента и размера запроса (первичная)
    if zipfile.content_type not in ("application/zip","application/x-zip-compressed","application/octet-stream"):
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
                    if r.status_code != 200 or r.headers.get("content-type","").split(";")[0] != "application/pdf":
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
