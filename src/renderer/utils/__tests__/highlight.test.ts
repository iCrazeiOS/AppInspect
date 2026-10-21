import { describe, expect, it } from "bun:test";
import { highlightLogos, highlightObjCMethod } from "../highlight";

describe("highlightObjCMethod", () => {
	it("highlights sign, types, selector and arguments", () => {
		const html = highlightObjCMethod("-(void)setBatteryLevelDidChange:(float)arg0");
		expect(html).toContain('<span class="hl-sign">-</span>');
		expect(html).toContain('<span class="hl-type">void</span>');
		expect(html).toContain('<span class="hl-selector">setBatteryLevelDidChange</span>');
		expect(html).toContain('<span class="hl-punct">:</span>');
		expect(html).toContain('<span class="hl-type">float</span>');
		expect(html).toContain('<span class="hl-arg">arg0</span>');
	});

	it("treats a no-argument method name as a selector", () => {
		const html = highlightObjCMethod("+(id)sharedInstance");
		expect(html).toContain('<span class="hl-sign">+</span>');
		expect(html).toContain('<span class="hl-type">id</span>');
		expect(html).toContain('<span class="hl-selector">sharedInstance</span>');
		expect(html).not.toContain("hl-arg");
	});

	it("escapes generics in types", () => {
		const html = highlightObjCMethod("-(NSArray<NSString *> *)names:(id)arg0");
		expect(html).toContain("NSArray&lt;NSString *&gt; *");
		expect(html).not.toContain("<NSString");
	});
});

describe("highlightLogos", () => {
	it("highlights Logos directives and the ObjC declaration", () => {
		const html = highlightLogos(
			"%hook Foo\n-(void)bar:(id)arg0 {\n    %orig;\n    return orig;\n}\n%end"
		);
		expect(html).toContain('<span class="hl-keyword">%hook</span>');
		expect(html).toContain('<span class="hl-type">Foo</span>');
		expect(html).toContain('<span class="hl-sign">-</span>');
		expect(html).toContain('<span class="hl-selector">bar</span>');
		expect(html).toContain('<span class="hl-arg">arg0</span>');
		expect(html).toContain('<span class="hl-keyword">%orig</span>');
		expect(html).toContain('<span class="hl-keyword">return</span>');
		expect(html).toContain('<span class="hl-arg">orig</span>');
		expect(html).toContain('<span class="hl-keyword">%end</span>');
	});

	it("highlights strings and function calls", () => {
		const html = highlightLogos('NSLog(@"%@", arg0);');
		expect(html).toContain('<span class="hl-selector">NSLog</span>');
		expect(html).toContain('<span class="hl-string">@&quot;%@&quot;</span>');
		expect(html).toContain('<span class="hl-arg">arg0</span>');
	});

	it("highlights %c class references", () => {
		const html = highlightLogos("%c(Foo)");
		expect(html).toContain('<span class="hl-keyword">%c</span>');
		expect(html).toContain('<span class="hl-type">Foo</span>');
	});
});
