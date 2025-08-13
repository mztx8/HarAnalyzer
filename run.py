from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import json
from datetime import datetime
import os
from werkzeug.utils import secure_filename
from har_analyzer import HarAnalyzer

app = Flask(__name__)
CORS(app)  # 启用CORS支持

# 配置上传目录
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'har'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 确保上传目录存在
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/analyze-har', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({
            'success': False,
            'message': '没有选择文件'
        }), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({
            'success': False,
            'message': '没有选择文件'
        }), 400

    if file and allowed_file(file.filename):
        try:
            # 读取文件内容
            content = file.read()
            har_data = json.loads(content.decode('utf-8'))

            # 使用HAR分析器分析数据
            analyzer = HarAnalyzer(har_data)
            analysis_result = analyzer.analyze()

            return jsonify({
                "success": True,
                "data": analysis_result,
                "message": "HAR文件分析完成"
            })

        except json.JSONDecodeError:
            return jsonify({
                'success': False,
                'message': 'HAR文件格式错误，请确保是有效的JSON格式'
            }), 400
        except Exception as e:
            return jsonify({
                'success': False,
                'message': f'分析失败: {str(e)}'
            }), 500
    else:
        return jsonify({
            'success': False,
            'message': '文件类型不支持，请上传.har文件'
        }), 400

@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)

@app.route('/api/health', methods=['GET'])
def health_check():
    """健康检查接口"""
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "service": "HAR文件分析工具"
    })

@app.route('/favicon.ico')
def favicon():
    """处理favicon请求"""
    return '', 204

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8000)