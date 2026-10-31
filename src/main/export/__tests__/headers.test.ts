/**
 * Tests for ObjC header export (headers.ts).
 */

import { describe, expect, it } from "bun:test";
import type { ObjCCategory, ObjCClass, ObjCProtocol } from "../../../shared/types";
import { buildHeaders } from "../headers";

function cls(
	name: string,
	superclass: string | undefined,
	methods: { selector: string; signature: string }[] = [],
	protocols?: string[]
): ObjCClass {
	return { name, superclass, methods, protocols };
}

function protocol(name: string, overrides: Partial<Omit<ObjCProtocol, "name">> = {}): ObjCProtocol {
	return {
		name,
		instanceMethods: [],
		classMethods: [],
		optionalInstanceMethods: [],
		optionalClassMethods: [],
		...overrides
	};
}

function find(files: { name: string; content: string }[], name: string): string {
	const file = files.find((f) => f.name === name);
	expect(file).toBeDefined();
	return file!.content;
}

describe("buildHeaders", () => {
	it("writes a header per class and protocol", () => {
		const files = buildHeaders({
			classes: [
				cls("Base", "NSObject", [{ selector: "base", signature: "-(void)base" }]),
				cls(
					"Child",
					"Base",
					[
						{ selector: "doThing:", signature: "-(void)doThing:(id)arg0" },
						{ selector: "shared", signature: "+(id)shared" }
					],
					["Things"]
				)
			],
			protocols: ["Things"],
			protocolDetails: [
				protocol("Things", {
					instanceMethods: [
						{ selector: "requiredThing", signature: "-(void)requiredThing" }
					],
					optionalClassMethods: [
						{ selector: "optional:", signature: "+(void)optional:(int)arg0" }
					]
				})
			],
			binaryName: "Example"
		});

		expect(files.map((f) => f.name)).toEqual(["Things.h", "Base.h", "Child.h"]);

		const child = find(files, "Child.h");
		expect(child).toContain(`#import "Base.h"`);
		expect(child).toContain(`#import "Things.h"`);
		expect(child).toContain("@interface Child : Base <Things>");
		expect(child).toContain("-(void)doThing:(id)arg0;");
		expect(child).toContain("+(id)shared;");
		expect(child).toContain("//  Binary: Example");

		const things = find(files, "Things.h");
		expect(things).toContain("@protocol Things");
		expect(things).toContain("@required");
		expect(things).toContain("-(void)requiredThing;");
		expect(things).toContain("@optional");
		expect(things).toContain("+(void)optional:(int)arg0;");
	});

	it("forward-declares superclasses and protocols that are not exported", () => {
		const files = buildHeaders({
			classes: [
				cls("Controller", "UIViewController", [], ["UITableViewDataSource", "Exported"])
			],
			protocols: [],
			protocolDetails: []
		});

		const header = find(files, "Controller.h");
		expect(header).toContain("@class UIViewController;");
		expect(header).toContain("@protocol UITableViewDataSource;");
		expect(header).toContain(
			"@interface Controller : UIViewController <Exported, UITableViewDataSource>"
		);
		expect(header).toContain("#import <Foundation/Foundation.h>");
	});

	it("de-duplicates methods and normalises missing prefixes and semicolons", () => {
		const files = buildHeaders({
			classes: [
				cls("Thing", undefined, [
					{ selector: "foo", signature: "-(void)foo" },
					{ selector: "foo", signature: "-(void)foo;" },
					{ selector: "bar", signature: "bar" }
				])
			],
			protocols: [],
			protocolDetails: []
		});

		const header = find(files, "Thing.h");
		expect(header.match(/foo/g)?.length).toBe(1);
		expect(header).toContain("-(void)foo;");
		expect(header).toContain("-(id)bar;");
		expect(header).toContain("@interface Thing\n");
	});

	it("sanitises file names and resolves collisions", () => {
		const files = buildHeaders({
			classes: [cls("Weird:Name", undefined, [])],
			protocols: ["Weird/Name"],
			protocolDetails: []
		});

		expect(files.map((f) => f.name)).toEqual(["Weird_Name.h", "Weird_Name-2.h"]);
	});

	it("emits property declarations and an ivar block inside the interface", () => {
		const classWithMembers: ObjCClass = {
			name: "Widget",
			superclass: "NSObject",
			methods: [{ selector: "title", signature: "-(id)title" }],
			properties: [
				{
					name: "title",
					type: "NSString *",
					attributes: 'T@"NSString",C,N,V_title',
					attributeList: ["copy", "nonatomic"],
					ivar: "_title"
				}
			],
			ivars: [
				{ name: "_title", type: "NSString *", offset: 8 },
				{ name: "_count", type: "int", offset: 16 }
			]
		};

		const files = buildHeaders({
			classes: [classWithMembers],
			protocols: [],
			protocolDetails: []
		});

		const header = find(files, "Widget.h");
		expect(header).toContain("@interface Widget : NSObject");
		expect(header).toContain("{");
		expect(header).toContain("    NSString *_title;");
		expect(header).toContain("    int _count;");
		expect(header).toContain("}");
		expect(header).toContain("@property (copy, nonatomic) NSString *title;");
		expect(header).toContain("-(id)title;");
		// Ivars carry their hex offset; properties name their backing ivar.
		expect(header).toContain("    NSString *_title;  // offset: +0x8");
		expect(header).toContain("    int _count;        // offset: +0x10");
		expect(header).toContain("@property (copy, nonatomic) NSString *title;  // ivar: _title");
	});

	it("orders class methods before instance methods, each sorted", () => {
		const cls: ObjCClass = {
			name: "Ordered",
			superclass: "NSObject",
			methods: [
				{ selector: "zzz", signature: "-(void)zzz" },
				{ selector: "shared", signature: "+(id)shared" },
				{ selector: "aaa", signature: "-(void)aaa" },
				{ selector: "alloc", signature: "+(id)alloc" }
			]
		};
		const header = find(
			buildHeaders({ classes: [cls], protocols: [], protocolDetails: [] }),
			"Ordered.h"
		);
		// Both class methods appear before either instance method, and each block is sorted.
		expect(header.indexOf("+(id)alloc;")).toBeLessThan(header.indexOf("+(id)shared;"));
		expect(header.indexOf("+(id)shared;")).toBeLessThan(header.indexOf("-(void)aaa;"));
		expect(header.indexOf("-(void)aaa;")).toBeLessThan(header.indexOf("-(void)zzz;"));
	});

	it("writes a Class+Category.h header per category", () => {
		const category: ObjCCategory = {
			name: "MD5",
			className: "NSString",
			methods: [{ selector: "md5", signature: "-(id)md5" }],
			properties: [],
			protocols: []
		};

		const files = buildHeaders({
			classes: [],
			categories: [category],
			protocols: [],
			protocolDetails: []
		});

		const header = find(files, "NSString+MD5.h");
		expect(header).toContain("@class NSString;");
		expect(header).toContain("@interface NSString (MD5)");
		expect(header).toContain("-(id)md5;");
		expect(header).toContain("@end");
	});

	it("emits empty protocol headers when only the name is known", () => {
		const files = buildHeaders({
			classes: [],
			protocols: ["Bare"],
			protocolDetails: []
		});

		const header = find(files, "Bare.h");
		expect(header).toContain("@protocol Bare");
		expect(header).toContain("@end");
		expect(header).not.toContain("@required");
	});
});
