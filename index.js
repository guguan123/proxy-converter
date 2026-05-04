const net = require('net');

/**
 * Converts a list of proxy configurations into V2Ray subscription links.
 * @param {Array<Object>} proxies - An array of proxy configuration objects.
 * @returns {Array<string>} An array of V2Ray formatted subscription links.
 */
function convertClashProxiesToV2rayLinks(proxies) {
	const lines = [];

	for (const p of proxies) {
		try {
			let link = null;

			switch (p.type) {

				// SOCKS
				case 'socks5': {
					// socks://username:password@server:port#name
					link = `socks5://${p.username && p.password ? encodeURIComponent(p.username) + ':' + encodeURIComponent(p.password) + '@' : ''}${normalize_server_address(p.server)}:${p.port}#${encodeURIComponent(p.name)}`;
					break;
				}

				// Shadowsocks
				case 'ss': {
					// ss://base64(method:password)@server:port#name
					link = `ss://${Buffer.from(`${p.cipher}:${p.password}`).toString('base64')}@${normalize_server_address(p.server)}:${p.port}`;

					if (p.plugin === 'v2ray-plugin' && p['plugin-opts']) {
							const parts = ['v2ray-plugin'];

							if (p['plugin-opts'].mode) parts.push(`mode=${p['plugin-opts'].mode}`);
							if (p['plugin-opts'].host) parts.push(`host=${p['plugin-opts'].host}`);
							if (p['plugin-opts'].path) parts.push(`path=${p['plugin-opts'].path}`);

							if (p['plugin-opts'].tls === true) parts.push('tls');
							if (p['plugin-opts'].mux === true || p['plugin-opts'].mux === 0) parts.push(`mux=${p['plugin-opts'].mux}`);

							// 连接符分号 ;
							const pluginValue = parts.join(';');
							// 处理转义
							const params = new URLSearchParams();
							params.append('plugin', pluginValue);
							link += `/?${params.toString()}`;
						} else if (p.plugin === 'obfs' && p['plugin-opts']) {
							const pluginValue = `obfs-local;obfs=${p['plugin-opts'].mode || 'http'};obfs-host=${p['plugin-opts'].host || ''}`;
							link += `/?${new URLSearchParams({ plugin: pluginValue }).toString()}`;
						}

						link += `#${encodeURIComponent(p.name)}`;
						break;
				}

				// VMess
				case 'vmess': {
					// vmess:// base64(json)
					let vmessObj = {
						v: "2",
						ps: p.name,
						add: p.server,
						port: p.port,
						id: p.uuid,
						aid: p.alterId,
						scy: p.cipher,
						net: p.network || "tcp",
						type: "none",
						...(p["ws-opts"]?.["headers"]?.Host && { host: p["ws-opts"]["headers"].Host }),
						...(p["ws-opts"]?.path && { path: p["ws-opts"].path }),
						...(p.servername && { sni: p.servername }),
						...(p.tls && { tls: "tls" }),
						...(p["skip-cert-verify"] && { insecure: 1 }),
						// 只有当 p.alpn 有值时，才添加 alpn 字段
						...(p.alpn?.length && { alpn: p.alpn.join(",") })
					};
					link = `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`;
					break;
				}

				// VLESS
				case 'vless': {
					// vless://uuid@server:port?encryption=none&security=tls&type=ws&host=xxx&path=yyy&sni=zzz#name
					let vlessParams = new URLSearchParams();

					// encryption
					vlessParams.set('encryption', p.encryption || 'none');

					// 控流
					if (p.flow) vlessParams.set('flow', p.flow);

					// 传输层类型
					vlessParams.set('type', p.network || 'tcp');

					if (p.tls) {
						// 加密类型 (reality, tls)
						vlessParams.set('security', p["reality-opts"] ? 'reality' : 'tls');

						// TLS配置
						if (p.servername) vlessParams.set('sni', p.servername);
						if (p["client-fingerprint"]) vlessParams.set('fp', p["client-fingerprint"]);
						if (p["skip-cert-verify"]) vlessParams.set('allowInsecure', '1');

						// REALITY
						if (p["reality-opts"]?.["public-key"]) vlessParams.set('pbk', p["reality-opts"]["public-key"]);
						if (p["reality-opts"]?.["short-id"]) vlessParams.set('sid', p["reality-opts"]["short-id"]);

						// ECH
						if (p['ech-opts'] && p['ech-opts'].enable) {
							if (p['ech-opts'].config) {
								// 静态配置，直接塞入 Base64 字符串
								vlessParams.set('ech', p['ech-opts'].config);
							} else if (p['ech-opts']['query-server-name']) {
								// 动态解析，host+doh 的格式
								vlessParams.set('ech', `${p['ech-opts']['query-server-name']}+https://dns.alidns.com/dns-query`);
							}
						}
					} else {
						vlessParams.set('security', 'none');
					}

					// 传输层配置
					if (p.network === 'ws' && p["ws-opts"]) {
						if (p["ws-opts"]?.headers?.Host) vlessParams.set('host', p["ws-opts"].headers.Host);
						if (p["ws-opts"]?.path) vlessParams.set('path', p["ws-opts"].path);
					}

					const vlessQuery = vlessParams.toString();
					link = `vless://${p.uuid}@${normalize_server_address(p.server)}:${p.port}${vlessQuery ? '?' + vlessQuery : ''}#${encodeURIComponent(p.name)}`;
					break;
				}

				// Trojan
				case 'trojan': {
					// trojan://password@server:port?security=tls&sni=xxx&type=ws&host=yyy&path=zzz#name
					let trojanParams = new URLSearchParams();
					if (p.tls !== false) {
						trojanParams.set('security', p["reality-opts"] ? 'reality' : 'tls');
						if (p.sni) trojanParams.set('sni', p.sni);
						if (p["skip-cert-verify"]) trojanParams.set('allowInsecure', '1');
					} else {
						trojanParams.set('security', 'none');
					}

					if (p.network && p.network !== 'tcp') {
						trojanParams.set('type', p.network);
						if (p.network === 'ws') {
							if (p["ws-opts"]?.["headers"]?.Host) trojanParams.set('host', p["ws-opts"]["headers"].Host);
							if (p["ws-opts"]?.path) trojanParams.set('path', p["ws-opts"].path);
						}
						if (p.network === 'grpc') {
							if (p["grpc-opts"]?.["grpc-service-name"]) {
								trojanParams.set('serviceName', p["grpc-opts"]["grpc-service-name"]);
							}
						}
					}

					const tQuery = trojanParams.toString();
					link = `trojan://${encodeURIComponent(p.password)}@${normalize_server_address(p.server)}:${p.port}${tQuery ? '?' + tQuery : ''}#${encodeURIComponent(p.name)}`;
					break;
				}

				// Hysteria2
				case 'hysteria2': {
					// hysteria2://auth@server:port?insecure=1&sni=xxx&obfs=xxx&obfs-password=yyy#name
					const hy2Params = new URLSearchParams();

					// sni
					if (p.sni) hy2Params.set('sni', p.sni);

					// 端口跳跃（可选）, 将 Clash 的 '/' 替换为 URL 规范的 ','
					if (p.ports) hy2Params.set('mport', String(p.ports).replaceAll('/', ',').replace(/\s+/g, ''));

					// 禁用TLS证书验证
					if (p["skip-cert-verify"]) hy2Params.set('insecure', '1');

					// Obfuscation
					if (p.obfs) {
						hy2Params.set('obfs', p.obfs);
						if (p["obfs-password"]) hy2Params.set('obfs-password', p["obfs-password"]);
					}

					// 下载/上传速度限制（可选）
					if (p.up) hy2Params.set('up', p.up);
					if (p.down) hy2Params.set('down', p.down);

					const hy2Query = hy2Params.toString();
					
					link = `hysteria2://${encodeURIComponent(p.password)}@${normalize_server_address(p.server)}:${p.port}${hy2Query ? '?' + hy2Query : ''}#${encodeURIComponent(p.name)}`;
					break;
				}

				// TUIC
				case 'tuic': {
					// tuic://uuid:password@server:port?congestion_control=bbr&alpn=h3&sni=xxx#name
					let tuicParams = new URLSearchParams();

					// 拥塞控制
					if (p['congestion-controller']) tuicParams.set('congestion_control', p['congestion-controller']);

					// UDP RELAY 模式
					if (p['udp-relay-mode']) tuicParams.set('udp_relay_mode', p['udp-relay-mode']);

					// TLS 相关
					if (p.sni) tuicParams.set('sni', p.sni);
					if (p.alpn && p.alpn.length) tuicParams.set('alpn', p.alpn.join(','));
					if (p['skip-cert-verify']) tuicParams.set('allow_insecure', '1');
					if (p['disable-sni']) tuicParams.set('disable_sni', '1');

					const tuicQuery = tuicParams.toString();
					link = `tuic://${p.uuid}:${p.password}@${normalize_server_address(p.server)}:${p.port}${tuicQuery ? '?' + tuicQuery : ''}#${encodeURIComponent(p.name)}`;
					break;
				}

				// AnyTLS
				case 'anytls': {
					// anytls://password@server:port?sni=xxx&insecure=1#name
					const anyParams = new URLSearchParams();

					// sni (优先用 servername，和其他 tls 节点保持一致)
					if (p.sni) anyParams.set('sni', p.sni);

					// 跳过证书验证
					if (p["skip-cert-verify"]) anyParams.set('insecure', '1');

					if (p.alpn && p.alpn.length) anyParams.set('alpn', p.alpn.join(','));

					// 如果以后有更多参数（比如 obfs、padding 等），可以继续在这里加
					// 目前官方实现里 password 基本就是必填的，基本没其他常用 query 参数

					const query = anyParams.toString();
					link = `anytls://${encodeURIComponent(p.password)}@${normalize_server_address(p.server)}:${p.port}${query ? '?' + query : ''}#${encodeURIComponent(p.name)}`;
					break;
				}

				default:
					break;
			}

			if (link) lines.push(link);
		} catch (nodeError) {
			console.error(`Skipping node [${p.name || 'Unknown'}], reason:`, nodeError.message);
		}
	}

	return lines;
}

/**
 * Normalizes a server address string, ensuring IPv6 addresses are enclosed in square brackets.
 * @param {string} server - The server address string.
 * @returns {string} The normalized server address string.
 */
function normalize_server_address(server) {
	if (!server) return server;

	// Check if it is a valid IPv6 address
	if (net.isIPv6(server)) return `[${server}]`; // If so, bracket it

	// Otherwise, return as is
	return server;
}

module.exports = {
	convertClashProxiesToV2rayLinks
};
