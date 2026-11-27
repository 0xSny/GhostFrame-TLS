'use strict';
'require view';
'require fs';
'require rpc';
'require ui';

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: ['name'],
	expect: { '': {} }
});

return view.extend({
	handleSaveApply: null,
	handleSave: null,
	handleReset: null,

	load: function() {
		return Promise.all([
			callServiceList('kbox').catch(function() { return {}; }),
			fs.trimmed('/etc/kbox/admin.token').catch(function() { return ''; })
		]).then(function(res) {
			return { svc: res[0], adminToken: res[1] || '' };
		});
	},

	getDirectConsoleURL: function() {
		return '/kbox/';
	},

	execService: function(action) {
		return fs.exec('/etc/init.d/kbox', [action]).then(function() {
			window.setTimeout(function() {
				window.location.reload();
			}, 900);
		}).catch(function(err) {
			ui.addNotification(null, E('p', {}, '操作失败: ' + err.message), 'error');
		});
	},

	render: function(loaded) {
		var data = (loaded && loaded.svc) ? loaded.svc : (loaded || {});
		var adminToken = (loaded && loaded.adminToken) ? String(loaded.adminToken).trim() : '';
		var running = false;
		if (data && data['kbox'] && data['kbox'].instances) {
			var insts = data['kbox'].instances;
			for (var k in insts) {
				if (insts[k] && insts[k].running) {
					running = true;
					break;
				}
			}
		}

		var directUrl = this.getDirectConsoleURL();
		var iframeSrc = '/kbox/';

		var badge = E('span', {
			style: 'display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;' +
				(running ? 'background:rgba(16,185,129,.16);color:#10b981;border:1px solid rgba(16,185,129,.45);'
				         : 'background:rgba(244,63,94,.16);color:#f43f5e;border:1px solid rgba(244,63,94,.45);')
		}, running ? '● KestrelBox 运行中' : '○ KestrelBox 已停止');

		var toolbar = E('div', {
			style: 'display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;background:#0c1324;color:#e6eefc;border:1px solid #1d2a49;border-radius:12px;padding:12px 16px;margin-bottom:12px;'
		}, [
			E('div', { style: 'display:flex;align-items:center;gap:12px;flex-wrap:wrap;' }, [
				E('strong', { style: 'font-size:15px;' }, 'KestrelBox 旁路由透明网关'),
				badge
			]),
			E('div', { style: 'display:flex;gap:8px;flex-wrap:wrap;' }, [
				E('a', {
					href: directUrl,
					target: '_blank',
					rel: 'noopener noreferrer',
					class: 'cbi-button cbi-button-action'
				}, '独立标签页打开控制台 (' + window.location.hostname + ':19080)'),
				E('button', {
					class: 'cbi-button cbi-button-apply',
					click: ui.createHandlerFn(this, function() { return this.execService('restart'); })
				}, running ? '重启服务' : '启动服务'),
				running ? E('button', {
					class: 'cbi-button cbi-button-reset',
					click: ui.createHandlerFn(this, function() { return this.execService('stop'); })
				}, '停止服务') : ''
			])
		]);

		var frame = E('iframe', {
			src: iframeSrc,
			style: 'width:100%;height:calc(100dvh - 150px);min-height:600px;border:1px solid #1d2a49;border-radius:14px;background:#060913;'
		});

		var httpsNotice = E('div', {
			style: 'display:none;background:#0c1324;color:#e6eefc;border:1px solid rgba(245,158,11,.45);border-radius:14px;padding:28px 24px;text-align:center;'
		}, [
			E('h3', { style: 'margin:0 0 10px;color:#fbbf24;' }, 'HTTPS 混合内容安全拦截提示'),
			E('p', { style: 'margin:0 0 16px;color:#94a3b8;font-size:14px;line-height:1.7;' },
				'当前正通过 HTTPS 访问 LuCI，但同源反代 /kbox/ 未响应；浏览器安全策略会拦截在 HTTPS iframe 内嵌入 HTTP :19080 页面（防止空白页）。'),
			E('a', {
				href: directUrl,
				target: '_blank',
				rel: 'noopener noreferrer',
				class: 'cbi-button cbi-button-action',
				style: 'padding:8px 18px;font-weight:700;'
			}, '在新标签页打开 KestrelBox 独立控制台 (' + directUrl + ')')
		]);

		// Verify uhttpd same-origin proxy /kbox/ and pair authenticated LuCI session if bootstrap token exists.
		var pairPromise = adminToken
			? fetch('/kbox/api/auth/login', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ password: adminToken })
			}).catch(function() {})
			: Promise.resolve();

		pairPromise.then(function() {
			return fetch('/kbox/api/auth/info', { cache: 'no-store' });
		}).then(function(res) {
			if (!res.ok) throw new Error('proxy unavailable');
		}).catch(function() {
			if (window.location.protocol === 'https:') {
				frame.style.display = 'none';
				httpsNotice.style.display = 'block';
			} else {
				frame.src = directUrl;
			}
		});

		return E('div', { style: 'padding:4px 0;' }, [toolbar, httpsNotice, frame]);
	}
});
