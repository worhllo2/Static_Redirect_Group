document.addEventListener('DOMContentLoaded', function() {
    // 读取配置
    const config = window.REDIRECT_CONFIG || {};
    const rulesIntermediate = window.RULES_INTERMEDIATE || {};
    const rulesDirect = window.RULES_DIRECT || {};
    const fallbackBase = config.fallback || "https://blog.142588.xyz";

    // 获取当前路径
    const path = window.location.pathname;
    
    // 处理路径匹配 (移除末尾的斜杠，除非是根路径)
    let lookupPath = path;
    if (path.length > 1 && path.endsWith('/')) {
        lookupPath = path.slice(0, -1);
    }

    // 辅助函数：解析规则值 (支持字符串或对象)
    function getRuleData(ruleValue) {
        if (typeof ruleValue === 'string') {
            return { url: ruleValue };
        } else if (typeof ruleValue === 'object' && ruleValue !== null) {
            return ruleValue;
        }
        return null;
    }

    // 检查是否过期
    function isExpired(ruleData) {
        if (!ruleData || !ruleData.expired_at) return false;
        
        try {
            const expireDate = new Date(ruleData.expired_at);
            // 如果日期无效，视为未过期
            if (isNaN(expireDate.getTime())) return false;
            
            const now = new Date();
            return now > expireDate;
        } catch (e) {
            console.error("Error parsing expiration date", e);
            return false;
        }
    }

    // 查找规则
    // 优先级: 1. 直接跳转 (Direct) 2. 中间页跳转 (Intermediate) 3. Fallback
    
    let target = null;
    let mode = 'fallback'; // direct, intermediate, fallback
    let ruleData = null;

    // 只要规则存在且未过期，就视为命中
    if (rulesDirect[lookupPath]) {
        ruleData = getRuleData(rulesDirect[lookupPath]);
        if (ruleData && !isExpired(ruleData)) {
            target = ruleData.url;
            // 如果包含多个 URL，强制进入中转页模式
            mode = (ruleData.urls && Array.isArray(ruleData.urls)) ? 'intermediate' : 'direct';
        }
    } 
    
    // 如果没有命中 Direct 规则，继续检查 Intermediate
    if (!target && rulesIntermediate[lookupPath]) {
        ruleData = getRuleData(rulesIntermediate[lookupPath]);
        if (ruleData && !isExpired(ruleData)) {
            target = ruleData.url;
            mode = 'intermediate';
        }
    }
    
    // 如果仍然没有目标，使用 Fallback
    if (!target) {
        // Fallback
        let base = fallbackBase;
        if (base.endsWith('/') && path.startsWith('/')) {
            base = base.slice(0, -1);
        } else if (!base.endsWith('/') && !path.startsWith('/')) {
            base = base + '/';
        }
        target = base + path;
        mode = 'direct'; 
    }

    // URL 构建逻辑
    const search = window.location.search;
    const hash = window.location.hash;
    let finalUrl = target;

    try {
        const url = new URL(target);
        const currentParams = new URLSearchParams(search);
        currentParams.forEach((value, key) => {
            url.searchParams.set(key, value);
        });
        if (hash) {
            url.hash = hash;
        }
        finalUrl = url.toString();
    } catch (e) {
        console.error("Invalid URL construction", e);
        finalUrl = target + search + hash;
    }

    // 安全检查：防止 XSS (例如 javascript: 协议)
    // 只允许 http, https 协议
    try {
        const checkUrl = new URL(finalUrl, window.location.origin);
        if (checkUrl.protocol !== 'http:' && checkUrl.protocol !== 'https:') {
            console.error("Blocked potentially unsafe redirect:", finalUrl);
            // 降级到安全页面或显示错误
            finalUrl = "https://note.142588.xyz/404"; 
            if (document.getElementById('url-display')) {
                document.getElementById('url-display').textContent = "Blocked unsafe URL";
            }
            // 强制阻断
            target = null;
        }
    } catch (e) {
        // 如果无法解析 URL，也视为不安全（或者它是相对路径，相对路径通常安全但我们这里预期是绝对路径）
        // 如果是相对路径，new URL(url, base) 会解析成功。
        // 我们的 target 预期是完整 URL 或 fallback 拼接后的 URL。
        // 如果 target 本身有问题，保持谨慎。
        console.error("URL check failed:", e);
    }

    // 执行逻辑
    if (mode === 'direct') {
        // 直接跳转
        // 显示 Loading...
        const urlDisplay = document.getElementById('url-display');
        if (urlDisplay) urlDisplay.textContent = "Redirecting to " + finalUrl;
        
        // 确保是安全协议才跳转 (双重保险)
        if (target !== null) {
            window.location.replace(finalUrl);
        }
    } else {
        // 中间页 (intermediate)
        // 更新 UI
        const urlDisplay = document.getElementById('url-display');
        const redirectLink = document.getElementById('redirect-link');
        const card = document.querySelector('.card');
        const titleElement = document.querySelector('.card h2');

        // 显示卡片 (如果有 hidden 类的话，这里可以移除)
        if (card) card.style.display = 'block';

        if (ruleData.title && titleElement) {
            titleElement.textContent = ruleData.title;
        }

        if (urlDisplay) {
            urlDisplay.textContent = ruleData.urls ? "请选择以下链接访问" : finalUrl;
        }

        if (redirectLink) {
            const buttonContainer = document.getElementById('button-container') || redirectLink.parentNode;
            
            if (ruleData.urls && Array.isArray(ruleData.urls)) {
                // 如果有多个 URL，隐藏原始按钮并创建新按钮
                redirectLink.style.display = 'none';
                
                ruleData.urls.forEach(item => {
                    const btn = document.createElement('a');
                    btn.className = 'btn';
                    btn.style.marginBottom = '0.5rem';
                    btn.textContent = item.name || item.url;
                    
                    try {
                        const checkUrl = new URL(item.url, window.location.origin);
                        if (checkUrl.protocol === 'http:' || checkUrl.protocol === 'https:') {
                            btn.href = item.url;
                        } else {
                            btn.style.pointerEvents = 'none';
                            btn.style.opacity = '0.5';
                            btn.textContent += " (Unsafe)";
                        }
                    } catch (e) {
                        btn.style.pointerEvents = 'none';
                        btn.style.opacity = '0.5';
                        btn.textContent += " (Invalid)";
                    }
                    
                    buttonContainer.appendChild(btn);
                });
            } else {
                // 确保是安全协议才设置 href
                if (target !== null) {
                    redirectLink.href = finalUrl;
                } else {
                    redirectLink.removeAttribute('href');
                    redirectLink.style.pointerEvents = 'none';
                    redirectLink.style.opacity = '0.5';
                    redirectLink.textContent = "Unsafe Link";
                }
            }
        }
    }
});
