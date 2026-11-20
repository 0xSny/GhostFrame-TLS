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
		return callServiceList('0ghost').catch(function() { return {}; });
	},

	getDirectConsoleURL: function() {
		return 'http://' + window.location.hostname + ':19080/';
	},

	execService: function(action) {
		return fs.exec('/etc/init.d/0ghost', [action]).then(function() {
			window.setTimeout(function() {
				window.location.reload();
			}, 900);
		}).catch(function(err) {
			ui.addNotification(null, E('p', {}, '操作失败: ' + err.message), 'error');
		});
	},

	render: function(data) {
		var running = false;
		if (data && data['0ghost'] && data['0ghost'].instances) {
			var insts = data['0ghost'].instances;
			for (var k in insts) {
				if (insts[k] && insts[k].running) {
					running = true;
					break;
				}
			}
		}

		var directUrl = this.getDirectConsoleURL();
		var iframeSrc = '/0ghost/';

		var badge = E('span', {
			style: 'display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;' +
				(running ? 'background:rgba(16,185,129,.16);color:#10b981;border:1px solid rgba(16,185,129,.45);'
				         : 'background:rgba(244,63,94,.16);color:#f43f5e;border:1px solid rgba(244,63,94,.45);')
		}, running ? '● 0Ghost 运行中' : '○ 0Ghost 已停止');

		var toolbar = E('div', {
			style: 'display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between;background:#0c1324;color:#e6eefc;border:1px solid #1d2a49;border-radius:12px;padding:12px 16px;margin-bottom:12px;'
		}, [
			E('div', { style: 'display:flex;align-items:center;gap:12px;flex-wrap:wrap;' }, [
				E('strong', { style: 'font-size:15px;' }, '0Ghost 旁路由透明网关'),
				badge
			]),
			E('div', { style: 'display:flex;gap:8px;flex-wrap:wrap;' }, [
				E('a', {
					href: directUrl,
					target: '_blank',
					rel: 'noopener noreferrer',
					class: 'cbi-button cbi-button-action'
				}, '独立全屏打开控制台 (' + window.location.hostname + ':19080)'),
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
			style: 'width:100%;height:calc(100vh - 180px);min-height:760px;border:1px solid #1d2a49;border-radius:14px;background:#060913;'
		});

		// Fallback to direct :19080 if uhttpd proxy_prefix /0ghost is unavailable over HTTP.
		fetch('/0ghost/api/status', { cache: 'no-store' }).then(function(res) {
			if (!res.ok) throw new Error('proxy unavailable');
		}).catch(function() {
			if (window.location.protocol === 'http:') {
				frame.src = directUrl;
			}
		});

		return E('div', { style: 'padding:4px 0;' }, [toolbar, frame]);
	}
});
