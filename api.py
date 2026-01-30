import os
import time
import json
import logging
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import text

from jose import JWTError, jwt
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from database import engine, Base, SessionLocal, User, Event, Rule, SystemMetadata, get_db
from utils import load_config


SECRET_KEY = "SUPER_SECRET_KEY_CHANGE_ME"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


logging.basicConfig(level=logging.INFO, filename='api_access.log', format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="YUSUF BARIŞ DURMUŞ")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.templating import Jinja2Templates




app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/")
async def read_dashboard(request: Request):
    try:
        return templates.TemplateResponse("dashboard.html", {"request": request})
    except Exception as e:
        logger.error(f"Error rendering dashboard: {e}")
        return f"Error rendering dashboard: {e}"

@app.get("/logs")
async def read_logs(request: Request):
    return templates.TemplateResponse("logs.html", {"request": request})

@app.get("/rules")
async def read_rules(request: Request):
    return templates.TemplateResponse("rules.html", {"request": request})

@app.get("/reports")
async def read_reports(request: Request):
    return templates.TemplateResponse("reports.html", {"request": request})



def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time
    logger.info(f"{request.method} {request.url.path} - {response.status_code} - {duration:.2f}s")
    return response


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()


@app.post("/token")
@limiter.limit("5/minute")
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not pwd_context.verify(form_data.password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/api/stats")
async def get_stats(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    total_events = db.query(Event).count()
    severity_dist = {}
    for row in db.execute(text("SELECT severity, COUNT(*) FROM events GROUP BY severity")):
        severity_dist[row[0]] = row[1]
    
    recent_events = db.query(Event).order_by(Event.timestamp.desc()).limit(10).all()
    
    critical_count = severity_dist.get('CRITICAL', 0)
    risk_level = "LOW"
    if critical_count > 10: risk_level = "CRITICAL"
    elif critical_count > 0: risk_level = "HIGH"
    
    return {
        "total_events": total_events,
        "severity_distribution": severity_dist,
        "recent_events": recent_events,
        "risk_level": risk_level
    }


@app.get("/api/logs")
async def get_logs(
    severity: Optional[str] = None, 
    user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    query = db.query(Event)
    if severity:
        query = query.filter(Event.severity == severity.upper())
    return query.order_by(Event.timestamp.desc()).limit(100).all()

@app.get("/api/logs/export")
async def export_logs(
    severity: Optional[str] = None, 
    user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    import csv
    import io
    from fastapi.responses import StreamingResponse

    query = db.query(Event)
    if severity:
        query = query.filter(Event.severity == severity.upper())
    
    events = query.order_by(Event.timestamp.desc()).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['Timestamp', 'Category', 'Rule', 'Severity', 'IP', 'Message'])
    
    for event in events:
        writer.writerow([
            event.timestamp,
            event.category,
            event.rule_name,
            event.severity,
            event.remote_ip,
            event.message
        ])
    
    output.seek(0)
    csv_content = output.getvalue()

    filename = f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    

    config = load_config()
    reports_dir = config.get('reports_dir', 'reports')
    if not os.path.exists(reports_dir):
        os.makedirs(reports_dir)
    
    with open(os.path.join(reports_dir, filename), 'w', encoding='utf-8') as f:
        f.write(csv_content)

    from database import ReportHistory

    try:
        new_report = ReportHistory(
            filename=filename,
            created_at=datetime.utcnow(),
            created_by=user.username
        )
        db.add(new_report)
        db.commit()
    except Exception as e:
        logger.error(f"Failed to save report history: {e}")

    response = StreamingResponse(
        iter([csv_content]), 
        media_type="text/csv"
    )
    response.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return response


@app.get("/api/rules")
async def get_rules_api(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(Rule).all()

@app.put("/api/rules/{rule_id}")
async def update_rule(rule_id: int, data: dict, user: User = Depends(get_current_user), db: Session = Depends(get_db)):

    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can modify rules")

    rule = db.query(Rule).filter(Rule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    
    for key, value in data.items():
        if hasattr(rule, key):
            setattr(rule, key, value)
    

    meta = db.query(SystemMetadata).filter(SystemMetadata.key == "rules_version").first()
    if meta:
        meta.value = str(int(meta.value) + 1)
    else:
        db.add(SystemMetadata(key="rules_version", value="1"))
    
    db.commit()
    return {"message": "Rule updated successfully"}


@app.get("/api/reports")
async def list_reports(user: User = Depends(get_current_user), db: Session = Depends(get_db)):

    from database import ReportHistory
    history = db.query(ReportHistory).order_by(ReportHistory.created_at.desc()).all()
    return history

@app.get("/api/reports/{filename}")
async def download_report(filename: str, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Verify ownership or Admin role
    from database import ReportHistory
    report = db.query(ReportHistory).filter(ReportHistory.filename == filename).first()
    
    if report:
        if user.role != 'admin' and report.created_by != user.username:
            raise HTTPException(status_code=403, detail="You do not have permission to download this report")
    
    else:
        if user.role != 'admin':
            raise HTTPException(status_code=403, detail="Report validation failed")

    config = load_config()
    reports_dir = config.get('reports_dir', 'reports')
    file_path = os.path.join(reports_dir, filename)
    if os.path.exists(file_path):
        return FileResponse(file_path)
    raise HTTPException(status_code=404, detail="Report not found")

@app.post("/api/users")
async def create_user(
    new_user: dict, 
    user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    # Enforce Admin Role
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admins can create users")


    if db.query(User).filter(User.username == new_user['username']).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = pwd_context.hash(new_user['password'])

    db_user = User(username=new_user['username'], password_hash=hashed_password, role="user")
    db.add(db_user)
    db.commit()
    return {"message": "User created successfully"}

@app.get("/api/me")
async def get_current_user_info(user: User = Depends(get_current_user)):
    return {
        "username": user.username,
        "role": user.role
    }


@app.websocket("/ws/events")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:

            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@app.post("/api/events/internal")
async def post_event_internal(event: dict):

    await manager.broadcast(json.dumps(event))
    return {"status": "ok"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
