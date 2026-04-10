/**
 * Empty state component with centered icon, message, and optional action button.
 */

export interface EmptyStateOptions {
	icon?: string;
	message: string;
	actionLabel?: string;
	onAction?: () => void;
}

export class EmptyState {
	private options: EmptyStateOptions;
	private container: HTMLElement | null = null;
	private root: HTMLElement | null = null;

	constructor(options: EmptyStateOptions) {
		this.options = options;
	}

	mount(container: HTMLElement): void {
		this.container = container;

		const root = document.createElement("div");
		root.className = "es-root";
		this.root = root;

		// Icon
		if (this.options.icon) {
			const icon = document.createElement("div");
			icon.className = "es-icon";
			icon.textContent = this.options.icon;
			root.appendChild(icon);
		}

		// Message
		const msg = document.createElement("p");
		msg.className = "es-message";
		msg.textContent = this.options.message;
		root.appendChild(msg);

		// Action button
		if (this.options.actionLabel) {
			const btn = document.createElement("button");
			btn.className = "es-action";
			btn.textContent = this.options.actionLabel;
			if (this.options.onAction) {
				btn.addEventListener("click", this.options.onAction);
			}
			root.appendChild(btn);
		}

		container.appendChild(root);
	}

	destroy(): void {
		if (this.root && this.container) {
			this.container.removeChild(this.root);
		}
		this.root = null;
		this.container = null;
	}
}
