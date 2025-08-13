from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
import json
from datetime import datetime
import os
from typing import List, Dict, Any
from har_analyzer import HarAnalyzer

app = FastAPI(title="HAR文件分析工具", description="用于分析浏览器抓包HAR文件的工具")

# 添加CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载静态文件目录
app.mount("/static", StaticFiles(directory="static"), name="static")

# 创建上传目录
os.makedirs("uploads", exist_ok=True)

from fastapi.responses import HTMLResponse

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """返回主页"""
    with open("static/index.html", "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), status_code=200)

@app.post("/api/analyze-har")
async def analyze_har(file: UploadFile = File(...)):
    """分析上传的HAR文件"""
    try:
        # 检查文件类型
        if not file.filename.endswith('.har'):
            raise HTTPException(status_code=400, detail="请上传.har文件")
        
        # 读取文件内容
        content = await file.read()
        har_data = json.loads(content.decode('utf-8'))
        
        # 使用HAR分析器分析数据
        analyzer = HarAnalyzer(har_data)
        analysis_result = analyzer.analyze()
        
        return {
            "success": True,
            "data": analysis_result,
            "message": "HAR文件分析完成"
        }
        
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="HAR文件格式错误，请确保是有效的JSON格式")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"分析失败: {str(e)}")

@app.get("/health")
async def health_check():
    """健康检查接口"""
    return {"status": "ok", "timestamp": datetime.now().isoformat()}

@app.get("/favicon.ico")
async def favicon():
    """处理favicon请求"""
    return {"status": "no favicon"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)