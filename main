import hmac
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException

from attendance import (
    SessionStillOpen,
    audit,
    correct_attendance,
    finalize_all_due,
    finalize_session,
    process_scan,
)
from database import db, init_db
from schemas import CorrectionRequest, ScanRequest, ScanResponse
from security import authenticate_device


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if not os.environ.get("ADMIN_KEY"):
        print("WARNING: ADMIN_KEY is not set; /admin/* endpoints will answer 503.")
    yield


app = FastAPI(title="NFC Attendance (V1 prototype)", lifespan=lifespan)


def require_admin(x_admin_key: str = Header()) -> None:
    expected = os.environ.get("ADMIN_KEY")
    if not expected:
        raise HTTPException(status_code=503, detail="ADMIN_KEY is not configured on the server")
    if not hmac.compare_digest(x_admin_key.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="invalid admin key")


@app.get("/health")
def health() -> dict:
    return {"ok": True}


# ------------------------------------------------------------ scanner API

@app.post("/scan", response_model=ScanResponse, response_model_exclude_none=True)
def scan(req: ScanRequest, x_device_id: str = Header(), x_device_key: str = Header()) -> dict:
    with db() as conn:
        authorized = authenticate_device(conn, x_device_id, x_device_key)
        if authorized:
            result = process_scan(conn, req.token, x_device_id)
        else:
            audit(conn, f"device:{x_device_id[:40]}", "device_auth_failed")
    if not authorized:
        raise HTTPException(status_code=401, detail="invalid device credentials")
    return result


# -------------------------------------------------------------- admin API
# One shared admin key for the prototype. Named staff accounts come later.

@app.post("/admin/sessions/{class_id}/finalize", dependencies=[Depends(require_admin)])
def finalize(class_id: int) -> dict:
    with db() as conn:
        try:
            return finalize_session(conn, class_id, actor="admin")
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc))
        except SessionStillOpen as exc:
            raise HTTPException(status_code=409, detail=f"session still open: {exc}")


@app.post("/admin/finalize-due", dependencies=[Depends(require_admin)])
def finalize_due() -> dict:
    with db() as conn:
        return {"sessions_finalized": finalize_all_due(conn, actor="admin")}


@app.post("/admin/attendance/correct", dependencies=[Depends(require_admin)])
def correct(req: CorrectionRequest) -> dict:
    with db() as conn:
        try:
            return correct_attendance(
                conn, req.student_id, req.class_id, req.new_status, req.reason, f"staff:{req.staff_name}"
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc))


@app.get("/admin/sessions/{class_id}/attendance", dependencies=[Depends(require_admin)])
def session_attendance(class_id: int) -> dict:
    with db() as conn:
        session = conn.execute("SELECT * FROM class_sessions WHERE class_id = ?", (class_id,)).fetchone()
        if session is None:
            raise HTTPException(status_code=404, detail="session not found")
        rows = conn.execute(
            "SELECT s.university_student_id, s.name, s.section, a.status, a.source, a.scan_time "
            "FROM attendance a JOIN students s ON s.student_id = a.student_id "
            "WHERE a.class_id = ? ORDER BY s.name",
            (class_id,),
        ).fetchall()
    return {"session": dict(session), "records": [dict(r) for r in rows]}


@app.get("/admin/audit", dependencies=[Depends(require_admin)])
def audit_trail(limit: int = 50) -> list[dict]:
    with db() as conn:
        rows = conn.execute(
            "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (max(1, min(limit, 500)),)
        ).fetchall()
    return [dict(r) for r in rows]
