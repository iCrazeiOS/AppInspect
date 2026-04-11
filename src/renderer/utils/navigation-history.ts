/**
 * Reusable back/forward navigation history stack.
 *
 * Tracks a linear history of states with browser-style semantics:
 * pushing a new state clears any forward history.
 */

export class NavigationHistory<T> {
	private history: T[] = [];
	private index = -1;
	private navigating = false;
	private onChange: (() => void) | null;

	constructor(onChange?: () => void) {
		this.onChange = onChange ?? null;
	}

	/** Push a new state. Clears forward history. No-op during back/forward. */
	push(state: T): void {
		if (this.navigating) return;
		if (this.index < this.history.length - 1) {
			this.history.splice(this.index + 1);
		}
		this.history.push(state);
		this.index = this.history.length - 1;
		this.onChange?.();
	}

	/** Go back one step. Returns the state or null if at the beginning. */
	back(): T | null {
		if (this.index <= 0) return null;
		this.index--;
		return this.history[this.index] ?? null;
	}

	/** Go forward one step. Returns the state or null if at the end. */
	forward(): T | null {
		if (this.index >= this.history.length - 1) return null;
		this.index++;
		return this.history[this.index] ?? null;
	}

	/** Set navigating flag to suppress push() during back/forward navigation. */
	setNavigating(value: boolean): void {
		this.navigating = value;
	}

	canGoBack(): boolean {
		return this.index > 0;
	}

	canGoForward(): boolean {
		return this.index < this.history.length - 1;
	}
}
