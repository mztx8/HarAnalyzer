import json
from datetime import datetime
from typing import List, Dict, Any
import re
from urllib.parse import urlparse

class HarAnalyzer:
    """HAR文件分析器"""
    
    def __init__(self, har_data: dict):
        self.har_data = har_data
        self.entries = har_data.get('log', {}).get('entries', [])
        
    def analyze(self) -> Dict[str, Any]:
        """主要分析方法"""
        return {
            "summary": self._get_summary(),
            "requests": self._analyze_requests(),
            "performance": self._analyze_performance(),
            "errors": self._analyze_errors(),
            "anomalies": self._analyze_anomalies(),  # 新增：异常检测
            "domains": self._analyze_domains(),
            "file_types": self._analyze_file_types(),
            "timeline": self._create_timeline()
        }
    
    def _get_summary(self) -> Dict[str, Any]:
        """获取概要信息"""
        total_requests = len(self.entries)
        successful_requests = len([e for e in self.entries if 200 <= e.get('response', {}).get('status', 0) < 400])
        failed_requests = total_requests - successful_requests
        
        # 计算总传输大小
        total_size = sum([
            e.get('response', {}).get('content', {}).get('size', 0) 
            for e in self.entries
        ])
        
        # 计算平均响应时间
        times = [e.get('time', 0) for e in self.entries]
        avg_response_time = sum(times) / len(times) if times else 0

        # 计算总耗时
        total_time = sum([e.get('time', 0) for e in self.entries])

        return {
            "total_requests": total_requests,
            "successful_requests": successful_requests,
            "failed_requests": failed_requests,
            "success_rate": f"{(successful_requests/total_requests*100):.1f}%" if total_requests > 0 else "0%",
            "avg_response_time": f"{avg_response_time:.2f}ms",
            "total_size": self._format_size(total_size),
            "total_time": f"{total_time:.2f}ms",
            "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def _analyze_requests(self) -> List[Dict[str, Any]]:
        """分析每个请求的详细信息"""
        requests = []
        
        for i, entry in enumerate(self.entries):
            request = entry.get('request', {})
            response = entry.get('response', {})
            timings = entry.get('timings', {})
            
            # 解析URL
            url = request.get('url', '')
            parsed_url = urlparse(url)
            
            # 获取IP地址
            server_ip = entry.get('serverIPAddress', 'N/A')
            
            # 计算状态
            status_code = response.get('status', 0)
            is_error = status_code >= 400 or status_code == 0
            
            # 获取响应大小
            content_size = response.get('content', {}).get('size', 0)
            
            # 分析请求时间
            start_time = entry.get('startedDateTime', '')
            total_time = entry.get('time', 0)
            
            request_info = {
                "index": i + 1,
                "method": request.get('method', 'GET'),
                "url": url,
                "domain": parsed_url.netloc,
                "path": parsed_url.path,
                "status_code": status_code,
                "status_text": response.get('statusText', ''),
                "is_error": is_error,
                "server_ip": server_ip,
                "content_size": self._format_size(content_size),
                "content_size_bytes": content_size,
                "total_time": f"{total_time:.2f}ms",
                "total_time_ms": total_time,
                "start_time": start_time,
                "content_type": self._get_content_type(response),
                "request_headers": self._format_headers(request.get('headers', [])),
                "response_headers": self._format_headers(response.get('headers', [])),
                "query_params": self._format_query_params(request.get('queryString', [])),
                "post_data": self._format_post_data(request.get('postData', {})),
                "response_content": self._get_response_preview(response.get('content', {})),
                "timings": {
                    "dns": timings.get('dns', -1),
                    "connect": timings.get('connect', -1),
                    "ssl": timings.get('ssl', -1),
                    "send": timings.get('send', -1),
                    "wait": timings.get('wait', -1),
                    "receive": timings.get('receive', -1)
                },
                "cache": entry.get('cache', {}),
                "error_details": self._get_error_details(entry) if is_error else None
            }
            
            requests.append(request_info)
        
        return requests
    
    def _analyze_performance(self) -> Dict[str, Any]:
        """分析性能指标"""
        if not self.entries:
            return {}
        
        times = [e.get('time', 0) for e in self.entries]
        sizes = [e.get('response', {}).get('content', {}).get('size', 0) for e in self.entries]
        
        return {
            "avg_response_time": f"{sum(times)/len(times):.2f}ms",
            "min_response_time": f"{min(times):.2f}ms",
            "max_response_time": f"{max(times):.2f}ms",
            "total_transfer_size": self._format_size(sum(sizes)),
            "avg_transfer_size": self._format_size(sum(sizes)/len(sizes)) if sizes else "0B",
            "slowest_requests": self._get_slowest_requests(5),
            "largest_requests": self._get_largest_requests(5)
        }
    
    def _analyze_errors(self) -> Dict[str, Any]:
        """分析错误请求"""
        error_entries = [e for e in self.entries if e.get('response', {}).get('status', 0) >= 400 or e.get('response', {}).get('status', 0) == 0]
        
        error_stats = {}
        detailed_errors = []

        for i, entry in enumerate(error_entries):
            status = entry.get('response', {}).get('status', 0)
            status_text = entry.get('response', {}).get('statusText', 'Unknown')
            key = f"{status} {status_text}"

            # 获取详细信息
            url = entry.get('request', {}).get('url', '')
            parsed_url = urlparse(url)
            server_ip = entry.get('serverIPAddress', 'N/A')

            # 找到该请求在原始entries中的索引
            original_index = None
            for j, orig_entry in enumerate(self.entries):
                if (orig_entry.get('request', {}).get('url', '') == url and
                    orig_entry.get('response', {}).get('status', 0) == status):
                    original_index = j + 1
                    break

            error_detail = {
                "url": url,
                "domain": parsed_url.netloc,
                "server_ip": server_ip,
                "method": entry.get('request', {}).get('method', 'GET'),
                "time": entry.get('startedDateTime', ''),
                "status": status,
                "status_text": status_text,
                "index": original_index or (i + 1),  # 使用原始索引或当前索引
                "error_analysis": self._get_error_analysis(status, url, server_ip, parsed_url.netloc),
                "response_headers": self._format_headers(entry.get('response', {}).get('headers', [])),
                "response_content": self._get_response_preview(entry.get('response', {}).get('content', {})),
                "timings": entry.get('timings', {})
            }

            if key not in error_stats:
                error_stats[key] = []
            error_stats[key].append(error_detail)
            detailed_errors.append(error_detail)

        return {
            "total_errors": len(error_entries),
            "error_rate": f"{(len(error_entries)/len(self.entries)*100):.1f}%" if self.entries else "0%",
            "error_breakdown": error_stats,
            "detailed_errors": detailed_errors
        }

    def _get_error_analysis(self, status: int, url: str, server_ip: str, domain: str) -> Dict[str, Any]:
        """获取错误分析和解决方案"""
        error_info = {
            400: {
                "category": "客户端错误",
                "title": "请求格式错误",
                "description": "客户端发送的请求格式不正确，服务器无法理解。",
                "possible_causes": [
                    "请求参数格式错误",
                    "请求头信息不完整",
                    "JSON格式错误",
                    "请求体过大"
                ],
                "solutions": [
                    "检查请求参数格式是否正确",
                    "验证请求头信息是否完整",
                    "检查JSON格式是否有效",
                    "确认请求体大小是否超过限制"
                ]
            },
            401: {
                "category": "认证错误",
                "title": "未授权访问",
                "description": "请求需要用户身份验证，但当前请求未提供有效的认证信息。",
                "possible_causes": [
                    "未提供认证信息",
                    "认证信息过期",
                    "认证信息格式错误",
                    "用户名或密码错误"
                ],
                "solutions": [
                    "重新登录获取新的认证信息",
                    "检查Token是否过期",
                    "确认用户名密码是否正确",
                    "联系管理员检查账户状态"
                ]
            },
            403: {
                "category": "权限错误",
                "title": "禁止访问",
                "description": "服务器理解请求，但拒绝执行，通常是权限不足。",
                "possible_causes": [
                    "用户权限不足、登录失效",
                    "IP地址被限制",
                    "访问频率过高"
                ],
                "solutions": [
                    "联系邮箱管理员申请相应权限",
                    f"将IP地址 {server_ip} 添加到白名单",
                    f"将域名 {domain} 添加到防火墙白名单",
                    "降低访问频率",
                    "检查API调用限制"
                ]
            },
            404: {
                "category": "资源不存在",
                "title": "页面或资源未找到",
                "description": "服务器无法找到请求的资源。",
                "possible_causes": [
                    "URL地址错误",
                    "资源已被移动或删除",
                    "网络连接问题",
                    "域名解析失败"
                ],
                "solutions": [
                    "检查URL地址是否正确",
                    f"确认域名 {domain} 是否可访问",
                    f"将IP地址 {server_ip} 添加到网络白名单",
                    f"将域名 {domain} 添加到防火墙白名单",
                    "联系网络管理员检查网络连接",
                    "检查DNS解析是否正常"
                ]
            },
            405: {
                "category": "方法错误",
                "title": "不允许的请求方法",
                "description": "请求的HTTP方法不被资源支持。",
                "possible_causes": [
                    "使用了错误的HTTP方法",
                    "服务器不支持该方法",
                    "API接口配置错误"
                ],
                "solutions": [
                    "检查API文档确认正确的HTTP方法",
                    "联系开发人员确认接口配置",
                    "尝试使用其他HTTP方法"
                ]
            },
            408: {
                "category": "超时错误",
                "title": "请求超时",
                "description": "服务器等待请求的时间过长，连接已断开。",
                "possible_causes": [
                    "网络连接不稳定",
                    "服务器响应慢",
                    "请求处理时间过长",
                    "防火墙阻挡"
                ],
                "solutions": [
                    "检查网络连接稳定性",
                    f"确认能否正常访问 {domain}",
                    f"将IP地址 {server_ip} 添加到网络白名单",
                    f"将域名 {domain} 添加到防火墙白名单",
                    "增加请求超时时间",
                    "联系网络管理员检查网络配置"
                ]
            },
            429: {
                "category": "限流错误",
                "title": "请求过于频繁",
                "description": "在给定时间内发送了太多请求。",
                "possible_causes": [
                    "API调用频率过高",
                    "触发了速率限制",
                    "并发请求过多"
                ],
                "solutions": [
                    "降低API调用频率",
                    "实现请求队列控制",
                    "增加请求间隔时间",
                    "联系服务提供商提高限额"
                ]
            },
            500: {
                "category": "服务器错误",
                "title": "内部服务器错误",
                "description": "服务器遇到未知错误，无法完成请求。",
                "possible_causes": [
                    "服务器代码错误",
                    "服务器配置问题",
                    "数据库连接失败",
                    "服务器资源不足"
                ],
                "solutions": [
                    "联系服务提供商报告错误",
                    "稍后重试请求",
                    "检查服务器状态",
                    "联系技术支持"
                ]
            },
            502: {
                "category": "网关错误",
                "title": "网关错误",
                "description": "作为网关或代理的服务器从上游服务器接收到无效响应。",
                "possible_causes": [
                    "上游服务器故障",
                    "网关配置错误",
                    "网络连接问题",
                    "负载均衡器问题"
                ],
                "solutions": [
                    f"检查是否能直接访问 {domain}",
                    f"将IP地址 {server_ip} 添加到网络白名单",
                    f"将域名 {domain} 添加到防火墙白名单",
                    "联系网络管理员检查网关配置",
                    "稍后重试请求"
                ]
            },
            503: {
                "category": "服务不可用",
                "title": "服务暂时不可用",
                "description": "服务器当前无法处理请求，通常是临时状态。",
                "possible_causes": [
                    "服务器维护中",
                    "服务器过载",
                    "服务临时停止",
                    "网络连接问题"
                ],
                "solutions": [
                    "稍后重试请求",
                    f"确认 {domain} 服务是否正常",
                    f"检查是否能访问IP地址 {server_ip}",
                    f"将域名 {domain} 添加到防火墙白名单",
                    "联系服务提供商确认服务状态"
                ]
            },
            504: {
                "category": "网关超时",
                "title": "网关超时",
                "description": "作为网关或代理的服务器没有及时从上游服务器收到响应。",
                "possible_causes": [
                    "上游服务器响应慢",
                    "网络延迟高",
                    "防火墙阻挡",
                    "服务器过载"
                ],
                "solutions": [
                    f"检查网络到 {domain} 的连通性",
                    f"将IP地址 {server_ip} 添加到网络白名单",
                    f"将域名 {domain} 添加到防火墙白名单",
                    "增加超时时间设置",
                    "联系网络管理员检查网络配置"
                ]
            }
        }

        # 特殊状态码处理
        if status == 0:
            return {
                "category": "网络连接错误",
                "title": "无法连接到服务器",
                "description": "浏览器无法与服务器建立连接。",
                "possible_causes": [
                    "网络连接断开",
                    "DNS解析失败",
                    "防火墙阻挡"
                ],
                "solutions": [
                    "检查网络连接",
                    f"确认域名 {domain} 是否可解析",
                    f"将IP地址 {server_ip} 添加到网络白名单",
                    f"将域名 {domain} 添加到防火墙白名单",
                    "联系网络管理员检查网络配置",
                    "尝试使用其他网络连接"
                ]
            }

        # 获取对应的错误信息
        error_data = error_info.get(status, {
            "category": "未知错误",
            "title": f"HTTP {status} 错误",
            "description": "遇到未知的HTTP状态码。",
            "possible_causes": ["服务器返回了非标准状态码"],
            "solutions": [
                "联系开发人员检查具体错误",
                f"确认 {domain} 服务是否正常",
                f"检查IP地址 {server_ip} 是否可访问"
            ]
        })

        # 添加网络白名单信息
        if server_ip != 'N/A':
            whitelist_info = {
                "ip": server_ip,
                "domain": domain,
                "whitelist_suggestions": [
                    f"防火墙白名单: {domain}",
                    f"IP白名单: {server_ip}",
                    f"端口: 443 (HTTPS) 或 80 (HTTP)"
                ]
            }
            error_data["whitelist_info"] = whitelist_info

        return error_data
    
    def _analyze_anomalies(self) -> Dict[str, Any]:
        """检测异常请求模式"""
        anomalies = {
            "redirect_loops": self._detect_redirect_loops(),
            "duplicate_requests": self._detect_duplicate_requests(),
            "suspicious_patterns": self._detect_suspicious_patterns(),
            "performance_issues": self._detect_performance_issues(),
            "security_concerns": self._detect_security_concerns()
        }

        # 统计异常总数
        total_anomalies = sum([
            len(anomalies["redirect_loops"]),
            len(anomalies["duplicate_requests"]),
            len(anomalies["suspicious_patterns"]),
            len(anomalies["performance_issues"]),
            len(anomalies["security_concerns"])
        ])

        anomalies["total_anomalies"] = total_anomalies
        anomalies["has_anomalies"] = total_anomalies > 0

        return anomalies

    def _detect_redirect_loops(self) -> List[Dict[str, Any]]:
        """检测重定向循环"""
        redirect_chains = {}
        redirect_loops = []

        for i, entry in enumerate(self.entries):
            status = entry.get('response', {}).get('status', 0)
            url = entry.get('request', {}).get('url', '')

            # 检测3xx重定向
            if 300 <= status < 400:
                location = None
                headers = entry.get('response', {}).get('headers', [])
                for header in headers:
                    if header.get('name', '').lower() == 'location':
                        location = header.get('value', '')
                        break

                if location:
                    # 记录重定向链
                    if url not in redirect_chains:
                        redirect_chains[url] = []
                    redirect_chains[url].append({
                        "index": i + 1,
                        "from_url": url,
                        "to_url": location,
                        "status": status,
                        "time": entry.get('startedDateTime', '')
                    })

        # 检测循环
        for url, chain in redirect_chains.items():
            if len(chain) > 3:  # 超过3次重定向可能有问题
                visited_urls = set()
                for redirect in chain:
                    if redirect["to_url"] in visited_urls:
                        redirect_loops.append({
                            "type": "重定向循环",
                            "severity": "高",
                            "url": url,
                            "chain_length": len(chain),
                            "chain": chain,
                            "description": f"检测到可能的重定向循环，重定向次数: {len(chain)}",
                            "suggestion": "检查服务器重定向配置，避免循环重定向"
                        })
                        break
                    visited_urls.add(redirect["from_url"])
            elif len(chain) > 1:
                redirect_loops.append({
                    "type": "频繁重定向",
                    "severity": "中",
                    "url": url,
                    "chain_length": len(chain),
                    "chain": chain,
                    "description": f"检测到频繁重定向，重定向次数: {len(chain)}",
                    "suggestion": "考虑优化重定向链，减少不必要的重定向"
                })

        return redirect_loops

    def _detect_duplicate_requests(self) -> List[Dict[str, Any]]:
        """检测重复请求"""
        url_requests = {}
        duplicate_groups = []

        # 按URL分组请求
        for i, entry in enumerate(self.entries):
            url = entry.get('request', {}).get('url', '')
            method = entry.get('request', {}).get('method', 'GET')
            key = f"{method}:{url}"

            if key not in url_requests:
                url_requests[key] = []

            url_requests[key].append({
                "index": i + 1,
                "url": url,
                "method": method,
                "time": entry.get('startedDateTime', ''),
                "status": entry.get('response', {}).get('status', 0),
                "duration": entry.get('time', 0)
            })

        # 检测重复
        for key, requests in url_requests.items():
            if len(requests) > 3:  # 超过3次相同请求
                # 计算时间间隔
                times = []
                for req in requests:
                    try:
                        dt = datetime.fromisoformat(req["time"].replace('Z', '+00:00'))
                        times.append(dt)
                    except:
                        continue

                if len(times) > 1:
                    time_span = (max(times) - min(times)).total_seconds()
                    avg_interval = time_span / (len(times) - 1) if len(times) > 1 else 0

                    severity = "高" if avg_interval < 1 else "中" if avg_interval < 10 else "低"

                    duplicate_groups.append({
                        "type": "重复请求",
                        "severity": severity,
                        "url": requests[0]["url"],
                        "method": requests[0]["method"],
                        "count": len(requests),
                        "time_span": f"{time_span:.1f}秒",
                        "avg_interval": f"{avg_interval:.1f}秒",
                        "requests": requests,
                        "description": f"相同请求重复 {len(requests)} 次，平均间隔 {avg_interval:.1f} 秒",
                        "suggestion": "检查是否存在重复提交、轮询过频或缓存失效等问题"
                    })

        return sorted(duplicate_groups, key=lambda x: x["count"], reverse=True)

    def _detect_suspicious_patterns(self) -> List[Dict[str, Any]]:
        """检测可疑模式"""
        suspicious = []

        # 检测大量失败请求
        error_count = len([e for e in self.entries if e.get('response', {}).get('status', 0) >= 400])
        total_count = len(self.entries)
        if total_count > 0 and error_count / total_count > 0.3:  # 超过30%失败率
            suspicious.append({
                "type": "高错误率",
                "severity": "高",
                "description": f"错误请求占比过高: {(error_count/total_count*100):.1f}%",
                "count": error_count,
                "total": total_count,
                "suggestion": "检查网络连接、服务器状态或认证配置"
            })

        # 检测异常大的响应
        large_responses = []
        for i, entry in enumerate(self.entries):
            size = entry.get('response', {}).get('content', {}).get('size', 0)
            if size > 10 * 1024 * 1024:  # 超过10MB
                large_responses.append({
                    "index": i + 1,
                    "url": entry.get('request', {}).get('url', ''),
                    "size": self._format_size(size),
                    "size_bytes": size
                })

        if large_responses:
            suspicious.append({
                "type": "异常大响应",
                "severity": "中",
                "description": f"检测到 {len(large_responses)} 个超大响应文件",
                "responses": large_responses,
                "suggestion": "检查是否需要分页加载或压缩响应内容"
            })

        # 检测异常慢的请求
        slow_requests = []
        for i, entry in enumerate(self.entries):
            duration = entry.get('time', 0)
            if duration > 30000:  # 超过30秒
                slow_requests.append({
                    "index": i + 1,
                    "url": entry.get('request', {}).get('url', ''),
                    "duration": f"{duration:.0f}ms",
                    "duration_ms": duration
                })

        if slow_requests:
            suspicious.append({
                "type": "超时请求",
                "severity": "中",
                "description": f"检测到 {len(slow_requests)} 个超时请求",
                "requests": slow_requests,
                "suggestion": "检查网络连接、服务器性能或增加请求超时时间"
            })

        return suspicious

    def _detect_performance_issues(self) -> List[Dict[str, Any]]:
        """检测性能问题"""
        issues = []

        if not self.entries:
            return issues

        # 检测DNS解析问题
        dns_issues = []
        for i, entry in enumerate(self.entries):
            dns_time = entry.get('timings', {}).get('dns', -1)
            if dns_time > 1000:  # DNS解析超过1秒
                dns_issues.append({
                    "index": i + 1,
                    "url": entry.get('request', {}).get('url', ''),
                    "dns_time": f"{dns_time}ms"
                })

        if dns_issues:
            issues.append({
                "type": "DNS解析缓慢",
                "severity": "中",
                "description": f"检测到 {len(dns_issues)} 个DNS解析缓慢的请求",
                "requests": dns_issues,
                "suggestion": "检查DNS服务器配置，考虑使用更快的DNS服务器"
            })

        # 检测连接建立问题
        connect_issues = []
        for i, entry in enumerate(self.entries):
            connect_time = entry.get('timings', {}).get('connect', -1)
            if connect_time > 3000:  # 连接建立超过3秒
                connect_issues.append({
                    "index": i + 1,
                    "url": entry.get('request', {}).get('url', ''),
                    "connect_time": f"{connect_time}ms"
                })

        if connect_issues:
            issues.append({
                "type": "连接建立缓慢",
                "severity": "高",
                "description": f"检测到 {len(connect_issues)} 个连接建立缓慢的请求",
                "requests": connect_issues,
                "suggestion": "检查网络连接质量，可能存在防火墙阻挡或网络不稳定"
            })

        # 检测SSL握手问题
        ssl_issues = []
        for i, entry in enumerate(self.entries):
            ssl_time = entry.get('timings', {}).get('ssl', -1)
            if ssl_time > 2000:  # SSL握手超过2秒
                ssl_issues.append({
                    "index": i + 1,
                    "url": entry.get('request', {}).get('url', ''),
                    "ssl_time": f"{ssl_time}ms"
                })

        if ssl_issues:
            issues.append({
                "type": "SSL握手缓慢",
                "severity": "中",
                "description": f"检测到 {len(ssl_issues)} 个SSL握手缓慢的请求",
                "requests": ssl_issues,
                "suggestion": "检查SSL证书配置或考虑优化SSL握手过程"
            })

        return issues

    def _detect_security_concerns(self) -> List[Dict[str, Any]]:
        """检测安全相关问题"""
        concerns = []

        # 检测HTTP请求（应该使用HTTPS）
        http_requests = []
        for i, entry in enumerate(self.entries):
            url = entry.get('request', {}).get('url', '')
            if url.startswith('http://'):
                http_requests.append({
                    "index": i + 1,
                    "url": url
                })

        if http_requests:
            concerns.append({
                "type": "不安全HTTP连接",
                "severity": "中",
                "description": f"检测到 {len(http_requests)} 个HTTP请求（建议使用HTTPS）",
                "requests": http_requests[:10],  # 只显示前10个
                "total_count": len(http_requests),
                "suggestion": "建议所有请求都使用HTTPS加密连接，特别是涉及敏感数据的请求"
            })

        # 检测认证失败
        auth_failures = []
        for i, entry in enumerate(self.entries):
            status = entry.get('response', {}).get('status', 0)
            if status in [401, 403]:
                auth_failures.append({
                    "index": i + 1,
                    "url": entry.get('request', {}).get('url', ''),
                    "status": status,
                    "method": entry.get('request', {}).get('method', 'GET')
                })

        if len(auth_failures) > 5:  # 超过5个认证失败
            concerns.append({
                "type": "频繁认证失败",
                "severity": "高",
                "description": f"检测到 {len(auth_failures)} 个认证失败请求",
                "requests": auth_failures,
                "suggestion": "检查认证配置，可能存在密码错误、权限不足或会话过期等问题"
            })

        # 检测可疑的User-Agent
        suspicious_ua = []
        for i, entry in enumerate(self.entries):
            headers = entry.get('request', {}).get('headers', [])
            for header in headers:
                if header.get('name', '').lower() == 'user-agent':
                    ua = header.get('value', '')
                    # 检测是否为空或异常短
                    if not ua or len(ua) < 20:
                        suspicious_ua.append({
                            "index": i + 1,
                            "url": entry.get('request', {}).get('url', ''),
                            "user_agent": ua or "空"
                        })
                    break

        if suspicious_ua:
            concerns.append({
                "type": "可疑User-Agent",
                "severity": "低",
                "description": f"检测到 {len(suspicious_ua)} 个可疑的User-Agent",
                "requests": suspicious_ua[:5],  # 只显示前5个
                "total_count": len(suspicious_ua),
                "suggestion": "检查客户端配置，确保User-Agent信息正确设置"
            })

        return concerns

    def _analyze_domains(self) -> Dict[str, Any]:
        """分析域名统计"""
        domain_stats = {}
        for entry in self.entries:
            url = entry.get('request', {}).get('url', '')
            domain = urlparse(url).netloc
            if domain not in domain_stats:
                domain_stats[domain] = {
                    "count": 0,
                    "total_size": 0,
                    "total_time": 0,
                    "errors": 0
                }
            
            domain_stats[domain]["count"] += 1
            domain_stats[domain]["total_size"] += entry.get('response', {}).get('content', {}).get('size', 0)
            domain_stats[domain]["total_time"] += entry.get('time', 0)
            
            if entry.get('response', {}).get('status', 0) >= 400:
                domain_stats[domain]["errors"] += 1
        
        # 格式化统计数据
        formatted_stats = []
        for domain, stats in domain_stats.items():
            formatted_stats.append({
                "domain": domain,
                "request_count": stats["count"],
                "total_size": self._format_size(stats["total_size"]),
                "avg_time": f"{stats['total_time']/stats['count']:.2f}ms" if stats["count"] > 0 else "0ms",
                "error_count": stats["errors"],
                "error_rate": f"{(stats['errors']/stats['count']*100):.1f}%" if stats["count"] > 0 else "0%"
            })
        
        return {
            "total_domains": len(domain_stats),
            "domain_stats": sorted(formatted_stats, key=lambda x: x["request_count"], reverse=True)
        }
    
    def _analyze_file_types(self) -> List[Dict[str, Any]]:
        """分析文件类型统计"""
        file_types = {}
        total_requests = len(self.entries)

        for entry in self.entries:
            content_type = self._get_content_type(entry.get('response', {}))
            if content_type not in file_types:
                file_types[content_type] = {
                    "count": 0,
                    "total_size": 0
                }

            file_types[content_type]["count"] += 1
            file_types[content_type]["total_size"] += entry.get('response', {}).get('content', {}).get('size', 0)

        formatted_types = []
        for file_type, stats in file_types.items():
            percentage = f"{(stats['count']/total_requests*100):.1f}%" if total_requests > 0 else "0%"
            formatted_types.append({
                "type": file_type,
                "count": stats["count"],
                "total_size": self._format_size(stats["total_size"]),
                "avg_size": self._format_size(stats["total_size"]/stats["count"]) if stats["count"] > 0 else "0B",
                "percentage": percentage
            })
        
        return sorted(formatted_types, key=lambda x: x["count"], reverse=True)
    
    def _create_timeline(self) -> List[Dict[str, Any]]:
        """创建时间轴数据"""
        timeline = []
        for i, entry in enumerate(self.entries):
            start_time = entry.get('startedDateTime', '')
            if start_time:
                try:
                    dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                    timeline.append({
                        "index": i + 1,
                        "time": dt.isoformat(),
                        "url": entry.get('request', {}).get('url', ''),
                        "method": entry.get('request', {}).get('method', 'GET'),
                        "status": entry.get('response', {}).get('status', 0),
                        "duration": entry.get('time', 0)
                    })
                except:
                    pass
        
        return sorted(timeline, key=lambda x: x["time"])
    
    def _get_slowest_requests(self, limit: int) -> List[Dict[str, Any]]:
        """获取最慢的请求"""
        sorted_entries = sorted(self.entries, key=lambda x: x.get('time', 0), reverse=True)
        slowest = []
        
        for entry in sorted_entries[:limit]:
            slowest.append({
                "url": entry.get('request', {}).get('url', ''),
                "method": entry.get('request', {}).get('method', 'GET'),
                "time": f"{entry.get('time', 0):.2f}ms",
                "status": entry.get('response', {}).get('status', 0)
            })
        
        return slowest
    
    def _get_largest_requests(self, limit: int) -> List[Dict[str, Any]]:
        """获取最大的请求"""
        sorted_entries = sorted(self.entries, 
                              key=lambda x: x.get('response', {}).get('content', {}).get('size', 0), 
                              reverse=True)
        largest = []
        
        for entry in sorted_entries[:limit]:
            size = entry.get('response', {}).get('content', {}).get('size', 0)
            largest.append({
                "url": entry.get('request', {}).get('url', ''),
                "method": entry.get('request', {}).get('method', 'GET'),
                "size": self._format_size(size),
                "status": entry.get('response', {}).get('status', 0)
            })
        
        return largest
    
    def _get_content_type(self, response: Dict) -> str:
        """获取内容类型"""
        headers = response.get('headers', [])
        for header in headers:
            if header.get('name', '').lower() == 'content-type':
                content_type = header.get('value', '').split(';')[0].strip()
                return content_type
        return 'unknown'
    
    def _format_headers(self, headers: List[Dict]) -> Dict[str, str]:
        """格式化请求头"""
        formatted = {}
        for header in headers:
            formatted[header.get('name', '')] = header.get('value', '')
        return formatted
    
    def _format_query_params(self, params: List[Dict]) -> Dict[str, str]:
        """格式化查询参数"""
        formatted = {}
        for param in params:
            formatted[param.get('name', '')] = param.get('value', '')
        return formatted
    
    def _format_post_data(self, post_data: Dict) -> Dict[str, Any]:
        """格式化POST数据"""
        if not post_data:
            return {}
        
        text = post_data.get('text', '')
        mime_type = post_data.get('mimeType', '')

        # 根据内容类型格式化
        if mime_type == 'application/json' and text:
            try:
                import json
                formatted_text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
                preview = formatted_text[:2000] + ('...' if len(formatted_text) > 2000 else '')
            except:
                preview = text[:1000] + ('...' if len(text) > 1000 else '')
        else:
            preview = text[:1000] + ('...' if len(text) > 1000 else '')

        return {
            "mime_type": mime_type,
            "text": preview,
            "full_content": text,  # 保存完整内容
            "params": post_data.get('params', []),
            "is_json": mime_type == 'application/json',
            "is_form": mime_type == 'application/x-www-form-urlencoded',
            "is_multipart": mime_type.startswith('multipart/')
        }
    
    def _get_response_preview(self, content: Dict) -> Dict[str, Any]:
        """获取响应内容预览"""
        if not content:
            return {}
        
        text = content.get('text', '')
        mime_type = content.get('mimeType', '')

        # 根据内容类型决定预览长度
        if mime_type.startswith('application/json'):
            try:
                # 尝试格式化JSON
                import json
                if text:
                    formatted_text = json.dumps(json.loads(text), indent=2, ensure_ascii=False)
                    preview = formatted_text[:2000] + ('...' if len(formatted_text) > 2000 else '')
                else:
                    preview = ''
            except:
                preview = text[:1000] + ('...' if len(text) > 1000 else '') if text else ''
        else:
            preview = text[:1000] + ('...' if len(text) > 1000 else '') if text else ''

        return {
            "size": content.get('size', 0),
            "mime_type": mime_type,
            "preview": preview,
            "full_content": text,  # 保存完整内容
            "encoding": content.get('encoding', ''),
            "is_json": mime_type.startswith('application/json'),
            "is_html": mime_type.startswith('text/html'),
            "is_image": mime_type.startswith('image/'),
            "is_text": mime_type.startswith('text/')
        }
    
    def _get_error_details(self, entry: Dict) -> Dict[str, Any]:
        """获取错误详情"""
        response = entry.get('response', {})
        status = response.get('status', 0)
        
        error_categories = {
            400: "客户端错误 - 请求格式错误",
            401: "未授权 - 需要身份验证",
            403: "禁止访问 - 权限不足",
            404: "资源未找到",
            405: "方法不允许",
            408: "请求超时",
            429: "请求过于频繁",
            500: "服务器内部错误",
            502: "网关错误",
            503: "服务不可用",
            504: "网关超时"
        }
        
        return {
            "status_code": status,
            "status_text": response.get('statusText', ''),
            "category": error_categories.get(status, "未知错误"),
            "url": entry.get('request', {}).get('url', ''),
            "method": entry.get('request', {}).get('method', 'GET')
        }
    
    def _format_size(self, size_bytes: int) -> str:
        """格式化文件大小"""
        if size_bytes == 0:
            return "0B"
        
        units = ['B', 'KB', 'MB', 'GB']
        unit_index = 0
        size = float(size_bytes)
        
        while size >= 1024 and unit_index < len(units) - 1:
            size /= 1024
            unit_index += 1
        
        return f"{size:.1f}{units[unit_index]}"