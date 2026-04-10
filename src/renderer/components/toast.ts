/**
 * Toast notification component
 *
 * Slide-in from top-right, auto-dismiss after 5 seconds, closeable with X button.
 * Supports stacking multiple toasts vertically.
 */

export type ToastType = "error" | "warning" | "info" | "success";

let container: HTMLDivElement | null = null;

function ensureContainer(): HTMLDivElement {
	if (container && document.body.contains(container)) return container;
	container = document.createElement("div");
	container.className = "toast-container";
	document.body.appendChild(container);
	return container;
}

export function showToast(message: string, type: ToastType = "error"): void {
	const root = ensureContainer();

	const toast = document.createElement("div");
	toast.className = `toast toast--${type}`;

	const icon = document.createElement("span");
	icon.className = "toast-icon";
	icon.textContent =
		type === "error"
			? "\u2716"
			: type === "warning"
				? "\u26A0"
				: type === "success"
					? "\u2714"
					: "\u2139";

	const text = document.createElement("span");
	text.className = "toast-message";
	text.textContent = message;

	const closeBtn = document.createElement("button");
	closeBtn.className = "toast-close";
	closeBtn.textContent = "\u00D7";
	closeBtn.addEventListener("click", () => dismiss(toast));

	toast.appendChild(icon);
	toast.appendChild(text);
	toast.appendChild(closeBtn);

	root.appendChild(toast);

	// Trigger slide-in on next frame
	requestAnimationFrame(() => {
		toast.classList.add("toast--visible");
	});

	// Auto-dismiss after 5 seconds
	const timer = setTimeout(() => dismiss(toast), 5000);
	(toast as any)._timer = timer;
}

function dismiss(toast: HTMLDivElement): void {
	clearTimeout((toast as any)._timer);
	toast.classList.remove("toast--visible");
	toast.classList.add("toast--exit");
	toast.addEventListener(
		"transitionend",
		() => {
			toast.remove();
		},
		{ once: true }
	);
	// Fallback removal if transitionend doesn't fire
	setTimeout(() => {
		if (toast.parentNode) toast.remove();
	}, 400);
}
