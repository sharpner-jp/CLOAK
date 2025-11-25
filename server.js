const express = require('express');
const axios = require('axios');
const crypto = require('crypto');
const cheerio = require('cheerio');
const url = require('url');
const { wrapper } = require('axios-cookiejar-support');
const { CookieJar } = require('tough-cookie');

const app = express();
const PORT = 3000;

// Cookie管理
const jar = new CookieJar();
const client = wrapper(axios.create({ jar }));

// 暗号化設定
const SECRET_KEY = crypto.scryptSync('wes-secret-key', 'salt', 32);
const IV_LENGTH = 16;

app.use(express.static('public'));
app.use(express.json());

function encrypt(text) {
    try {
        if (!text) return null;
        const iv = crypto.randomBytes(IV_LENGTH);
        const cipher = crypto.createCipheriv('aes-256-ctr', SECRET_KEY, iv);
        let encrypted = cipher.update(text);
        encrypted = Buffer.concat([encrypted, cipher.final()]);
        return iv.toString('hex') + ':' + encrypted.toString('hex');
    } catch (e) { return null; }
}

function decrypt(text) {
    try {
        const textParts = text.split(':');
        if (textParts.length < 2) return null;
        const iv = Buffer.from(textParts.shift(), 'hex');
        const encryptedText = Buffer.from(textParts.join(':'), 'hex');
        const decipher = crypto.createDecipheriv('aes-256-ctr', SECRET_KEY, iv);
        let decrypted = decipher.update(encryptedText);
        decrypted = Buffer.concat([decrypted, decipher.final()]);
        return decrypted.toString();
    } catch (e) { return null; }
}

function rewriteUrl(originalUrl, baseUrl) {
    if (!originalUrl) return '';
    if (originalUrl.startsWith('data:') || originalUrl.startsWith('#') || originalUrl.startsWith('mailto:') || originalUrl.startsWith('javascript:')) {
        return originalUrl;
    }
    try {
        if (originalUrl.startsWith('//')) {
             originalUrl = new url.URL(baseUrl).protocol + originalUrl;
        }
        const resolvedUrl = new url.URL(originalUrl, baseUrl).href;
        return `/proxy?__q=${encrypt(resolvedUrl)}`;
    } catch (e) {
        return originalUrl;
    }
}

function getInjectionScript(targetOrigin) {
    return `
    <script>
    (function() {
        window.__WES_ORIGIN__ = "${targetOrigin}";
        const noop = function() {};
        
        // History API 乗っ取り (SPAのURL書き換え対策)
        window.history.pushState = noop;
        window.history.replaceState = noop;

        const rewriteApiUrl = (inputUrl) => {
            if (!inputUrl) return inputUrl;
            if (inputUrl.startsWith('data:') || inputUrl.startsWith('#') || inputUrl.startsWith('javascript:')) return inputUrl;
            try {
                // すでにプロキシURLならそのまま
                if (inputUrl.includes('/proxy?__q=') || inputUrl.includes('/proxy-api?url=')) return inputUrl;

                const abs = new URL(inputUrl, window.__WES_ORIGIN__).href;
                // API用エンドポイントへ誘導
                return '/proxy-api?url=' + encodeURIComponent(abs);
            } catch(e) { return inputUrl; }
        };

        // location.reload() が呼ばれたら、現在の「元のURL」を再読み込みさせる
        try {
            window.location.reload = function() {
                const current = window.location.href;
                window.location.href = current;
            };
            
            // location.assign / replace
            window.location.assign = function(url) { window.location.href = rewriteApiUrl(url); };
            window.location.replace = function(url) { window.location.href = rewriteApiUrl(url); };
        } catch(e) {}

        window.open = function(url, target, features) {
            if (url) window.location.href = rewriteApiUrl(url);
            return window;
        };

        const originalFetch = window.fetch;
        window.fetch = async function(input, init) {
            let target = input instanceof Request ? input.url : input;
            return originalFetch(rewriteApiUrl(target), init);
        };

        const originalOpen = XMLHttpRequest.prototype.open;
        XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
            return originalOpen.apply(this, [method, rewriteApiUrl(url), async, user, password]);
        };

        // MutationObserver はタイトルの更新通知のために維持
        const observer = new MutationObserver((mutations) => {
            let shouldNotify = false;
            mutations.forEach((mutation) => {
                if (mutation.target.tagName === 'TITLE') shouldNotify = true;
                
                mutation.addedNodes.forEach((node) => {
                    if (node.tagName === 'A' || node.tagName === 'FORM') node.removeAttribute('target');
                    
                    if (node.tagName === 'A' && node.href && !node.href.includes('/proxy')) {
                         // 生のgetAttributeを使って相対パス解決前の値を確認しつつ書き換え
                         node.href = rewriteApiUrl(node.href);
                    }

                    if (node.tagName === 'IMG' && node.src && !node.src.includes('/proxy')) node.src = rewriteApiUrl(node.src);
                    if (node.tagName === 'SCRIPT' && node.src && !node.src.includes('/proxy')) node.src = rewriteApiUrl(node.src);
                });
            });
            // タイトル更新時の通知も不要であれば削除
            // if (shouldNotify) notifyParent(); 
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });

        document.addEventListener('click', function(e) {
            let target = e.target.closest('a, form');
            if (target) {
                target.removeAttribute('target');
                if (target.tagName === 'A') {
                    const href = target.getAttribute('href');
                    if (href && !href.startsWith('#') && !href.startsWith('javascript:') && !target.href.includes('/proxy')) {
                        e.preventDefault();
                        window.location.href = rewriteApiUrl(target.href);
                    }
                }
            }
        }, true);
        
        // 🚨 notifyParent関数および関連する呼び出しを完全に削除
        // これにより、iframe内のページがアドレスバーのURLを上書きするのを防ぎます。
        // タイトルのみの更新が必要な場合は、タイトル更新専用の postMessage ロジックを実装し直してください。
        
    })();
    </script>
    `;
}

const COMMON_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'ja,en-US;q=0.9,en;q=0.8',
    'Cache-Control': 'no-cache',
    'Upgrade-Insecure-Requests': '1',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-User': '?1'
};

app.get('/encrypt', (req, res) => {
    const u = req.query.url;
    if (!u) return res.json({error: 'url missing'});
    res.json({ result: encrypt(u) });
});

app.all('/proxy-api', async (req, res) => {
    const targetUrl = req.query.url;
    if (!targetUrl) return res.status(404).send('');

    try {
        const headers = { ...COMMON_HEADERS, 'Referer': new url.URL(targetUrl).origin + '/' };
        
        const response = await client({
            method: req.method,
            url: targetUrl,
            headers: headers,
            data: req.body,
            responseType: 'arraybuffer',
            validateStatus: () => true,
            maxRedirects: 5
        });

        Object.entries(response.headers).forEach(([key, value]) => {
            if (!['content-security-policy', 'x-frame-options', 'content-encoding', 'access-control-allow-origin'].includes(key.toLowerCase())) {
                res.setHeader(key, value);
            }
        });
        res.status(response.status).send(response.data);
    } catch (error) {
        res.status(500).send('');
    }
});

app.get('/proxy', async (req, res) => {
    let encryptedUrl = req.query.__q;
    if (!encryptedUrl) return res.status(400).send('No URL');

    let targetUrl = decrypt(encryptedUrl);
    if (!targetUrl) return res.status(400).send('Invalid URL');

    // 安全装置: 自分自身(localhost)へのプロキシをブロック
    if (targetUrl.includes('localhost:3000') || targetUrl.includes('127.0.0.1:3000')) {
        return res.status(400).send('Recursive proxy access denied');
    }

    // 検索パラメータ結合
    try {
        const currentUrlObj = new url.URL(targetUrl);
        const extraParams = new url.URLSearchParams(req.query);
        extraParams.delete('__q');
        
        extraParams.forEach((value, key) => {
            currentUrlObj.searchParams.append(key, value);
        });
        targetUrl = currentUrlObj.toString();
    } catch(e) {
        console.error('URL error:', e);
    }

    console.log(`[WES Access] GET ${targetUrl}`);

    try {
        const headers = { ...COMMON_HEADERS, 'Referer': new url.URL(targetUrl).origin + '/' };

        const response = await client.get(targetUrl, {
            headers: headers,
            responseType: 'arraybuffer',
            validateStatus: () => true
        });

        const contentType = response.headers['content-type'] || '';
        res.set('Content-Type', contentType);
        res.removeHeader('Content-Security-Policy');
        res.removeHeader('X-Frame-Options');
        res.removeHeader('X-Content-Type-Options');

        if (contentType.includes('text/html')) {
            let html = response.data.toString('utf-8');
            const $ = cheerio.load(html);
            const origin = new url.URL(targetUrl).origin;

            $('head').prepend(getInjectionScript(origin));
            $('base').remove();

            $('a, form').removeAttr('target');

            const attrs = ['href', 'src', 'action', 'data', 'poster'];
            $('*').each((_, el) => {
                attrs.forEach(attr => {
                    const val = $(el).attr(attr);
                    if (val) $(el).attr(attr, rewriteUrl(val, targetUrl));
                });
                const srcset = $(el).attr('srcset');
                if (srcset) {
                    const newSrcset = srcset.split(',').map(p => {
                        const [u, w] = p.trim().split(/\s+/);
                        return `${rewriteUrl(u, targetUrl)} ${w || ''}`;
                    }).join(', ');
                    $(el).attr('srcset', newSrcset);
                }
            });

            res.send($.html());
        } else {
            res.send(response.data);
        }
    } catch (error) {
        res.status(502).send(`WES Error: ${error.message}`);
    }
});

app.listen(PORT, () => {
    console.log(`WES running on http://localhost:${PORT}`);
});