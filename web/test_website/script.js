/**
 * AI-IDS Test Site — 前端脚本
 */
(function() {
    'use strict';
    console.log('AI-IDS Test Site loaded @', new Date().toISOString());

    // 加载系统状态
    fetch('/api/status')
        .then(function(resp) { return resp.json(); })
        .then(function(data) {
            var panel = document.getElementById('status-panel');
            if (panel) {
                panel.innerHTML =
                    '<p>✅ 服务器运行正常 | 时间: ' + data.time +
                    ' | PHP版本: ' + data.php_version + '</p>';
            }
        })
        .catch(function() {
            var panel = document.getElementById('status-panel');
            if (panel) panel.innerHTML = '<p>⚠️ 无法获取状态</p>';
        });

    // 搜索表单增强
    var searchForms = document.querySelectorAll('.search-box, form[action="/search"]');
    searchForms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            var input = form.querySelector('input[name="q"]');
            if (!input || !input.value.trim()) {
                e.preventDefault();
                alert('请输入搜索关键词');
            }
        });
    });
})();
