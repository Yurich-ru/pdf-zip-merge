from fastapi import FastAPI, UploadFile, File, HTTPException, Response
from fastapi.responses import HTMLResponse
from typing import List
import os, re, tempfile, zipfile
import httpx

STIRLING_BASE_URL = os.getenv("STIRLING_BASE_URL", "http://stirling-pdf:8080")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "200"))
ALLOWED_COUNT = int(os.getenv("ALLOWED_COUNT", "500"))

app = FastAPI(title="PDF ZIP Merge")

# Файлы должны называться строго 1.pdf, 2.pdf, 3.pdf и т.д.
name_re = re.compile(r"^(\d+)\.pdf$", re.IGNORECASE)


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


@app.post("/merge-zip")
async def merge_zip(zipfile: UploadFile = File(...)):
    if zipfile.content_type not in (
        "application/zip",
        "application/x-zip-compressed",
        "application/octet-stream",
    ):
        raise HTTPException(status_code=400, detail="Ожидался ZIP-файл")

    # Читаем содержимое zip
    contents = await zipfile.read()
    size_mb = len(contents) / (1024 * 1024)
    if size_mb > MAX_UPLOAD_MB:
        raise HTTPException(
            status_code=413, detail=f"Слишком большой ZIP (> {MAX_UPLOAD_MB} MB)"
        )

    tmp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    try:
        tmp_zip.write(contents)
        tmp_zip.flush()
        tmp_zip.close()
        if not zipfile_is_valid(tmp_zip.name):
            raise HTTPException(status_code=400, detail="Некорректный ZIP")

        with zipfile.ZipFile(tmp_zip.name, "r") as zf:
            members = [m for m in zf.namelist() if not m.endswith("/")]
            candidates = []
            for m in members:
                base = os.path.basename(m)
                m1 = name_re.match(base)
                if m1:
                    candidates.append((int(m1.group(1)), m))
            if not candidates:
                raise HTTPException(
                    status_code=400, detail="В ZIP нет файлов 1.pdf, 2.pdf, ..."
                )

            candidates.sort(key=lambda x: x[0])
            if len(candidates) > ALLOWED_COUNT:
                raise HTTPException(
                    status_code=400,
                    detail=f"Слишком много файлов (> {ALLOWED_COUNT})",
                )

            with tempfile.TemporaryDirectory() as tmpdir:
                extracted_paths: List[str] = []
                for _, member in candidates:
                    target = os.path.join(tmpdir, os.path.basename(member))
                    with zf.open(member) as src, open(target, "wb") as dst:
                        dst.write(src.read())
                    extracted_paths.append(target)

                # Собираем запрос в Stirling-PDF
                files = []
                for p in extracted_paths:
                    files.append(
                        ("fileInput", (os.path.basename(p), open(p, "rb"), "application/pdf"))
                    )
                data = {"sortType": "orderProvided"}

                url = f"{STIRLING_BASE_URL}/api/v1/general/merge-pdfs"
                async with httpx.AsyncClient(timeout=120) as client:
                    r = await client.post(url, files=files, data=data)
                    for _, f in files:
                        f[1].close()
                    if r.status_code != 200 or r.headers.get("content-type", "").split(";")[0] != "application/pdf":
                        raise HTTPException(
                            status_code=502,
                            detail=f"Stirling-PDF вернул ошибку {r.status_code}: {r.text[:300]}",
                        )
                    pdf_bytes = r.content

                return Response(
                    content=pdf_bytes,
                    media_type="application/pdf",
                    headers={"Content-Disposition": 'attachment; filename="merged.pdf"'},
                )
    finally:
        try:
            os.unlink(tmp_zip.name)
        except:
            pass


def zipfile_is_valid(path: str) -> bool:
    try:
        with zipfile.ZipFile(path, "r") as zf:
            bad = zf.testzip()
            return bad is None
    except:
        return False
