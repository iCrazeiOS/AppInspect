declare module "plist" {
	function parse(xml: string): unknown;
	function build(obj: unknown): string;
	export default { parse, build };
	export { parse, build };
}
