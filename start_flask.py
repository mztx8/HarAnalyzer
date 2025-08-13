#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAR文件分析工具 - Flask版本启动脚本
"""

import os
import sys

def main():
    print("="*60)
    print("HAR文件分析工具 - Flask版本")
    print("="*60)
    print("正在启动服务器...")
    print("访问地址: http://localhost:8000")
    print("API接口: http://localhost:8000/api/analyze-har")
    print("健康检查: http://localhost:8000/api/health")
    print("按 Ctrl+C 停止服务器")
    print("="*60)
    
    # 检查依赖
    try:
        import flask
        from flask_cors import CORS
        print("✓ Flask依赖检查通过")
    except ImportError as e:
        print(f"✗ 缺少依赖: {e}")
        print("请运行: pip install -r requirements.txt")
        sys.exit(1)
    
    # 启动服务器
    try:
        from run import app
        app.run(debug=True, host='0.0.0.0', port=8000)
    except KeyboardInterrupt:
        print("\n服务器已停止")
        sys.exit(0)
    except Exception as e:
        print(f"启动失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()