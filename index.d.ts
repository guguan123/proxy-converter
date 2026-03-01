declare module 'clash2sub' {
	/**
	 * 将 Clash 代理配置列表转换为 V2Ray 订阅链接
	 */
	export function convertClashProxiesToV2rayLinks(proxies: any[]): string[];
}
