"""
统一 JSON 响应格式

成功: { "code": 200, "msg": "success", "data": {...} }
失败: { "code": 4xx/5xx, "msg": "错误描述", "data": null }
"""

from flask import jsonify


def success(data=None, msg='success'):
    """返回成功响应"""
    return jsonify({
        'code': 200,
        'msg': msg,
        'data': data,
    })


def fail(code, msg, data=None):
    """返回失败响应"""
    return jsonify({
        'code': code,
        'msg': msg,
        'data': data,
    })


def bad_request(msg='请求参数错误'):
    return fail(400, msg)


def unauthorized(msg='未授权访问'):
    return fail(401, msg)


def not_found(msg='资源不存在'):
    return fail(404, msg)


def internal_error(msg='服务器内部错误'):
    return fail(500, msg)
