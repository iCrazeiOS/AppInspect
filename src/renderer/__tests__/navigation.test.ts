import { describe, expect, it } from "bun:test";
import {
	announce,
	clearPendingTargets,
	type NavigationTarget,
	navigateTo,
	registerNavigationHost,
	takePendingTarget
} from "../navigation";

describe("navigation pending targets", () => {
	it("is a no-op before a host is registered", () => {
		const session = "session-no-host";
		expect(() =>
			navigateTo(session, { sectionTab: "strings", kind: "string", offset: 16 })
		).not.toThrow();
		expect(takePendingTarget(session, "strings")).toBeUndefined();
	});

	it("passes the session and target to the host and consumes once", () => {
		const seen: Array<{ sessionId: string; target: NavigationTarget }> = [];
		registerNavigationHost((sessionId, target) => seen.push({ sessionId, target }));

		const target: NavigationTarget = { sectionTab: "symbols", kind: "symbol", name: "_main" };
		navigateTo("session-one", target);

		expect(seen).toEqual([{ sessionId: "session-one", target }]);
		expect(takePendingTarget("session-one", "symbols")).toEqual(target);
		expect(takePendingTarget("session-one", "symbols")).toBeUndefined();
	});

	it("keeps the last target when navigated repeatedly", () => {
		navigateTo("session-two", { sectionTab: "strings", kind: "string", offset: 1 });
		navigateTo("session-two", { sectionTab: "strings", kind: "string", offset: 2 });

		expect(takePendingTarget("session-two", "strings")).toEqual({
			sectionTab: "strings",
			kind: "string",
			offset: 2
		});
	});

	it("scopes targets to a session", () => {
		const first: NavigationTarget = { sectionTab: "files", kind: "file", path: "a.js" };
		const second: NavigationTarget = { sectionTab: "files", kind: "file", path: "b.js" };
		navigateTo("session-three", first);
		navigateTo("session-four", second);

		clearPendingTargets("session-three");

		expect(takePendingTarget("session-three", "files")).toBeUndefined();
		expect(takePendingTarget("session-four", "files")).toEqual(second);
	});
});

describe("navigation announcer", () => {
	it("does not throw without a DOM", () => {
		expect(() => announce("Opened string in Strings")).not.toThrow();
	});
});
