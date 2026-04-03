/**
 * Loading component with spinner, progress bar, and phase text.
 */

export class Loading {
  private container: HTMLElement | null = null;
  private root: HTMLElement | null = null;
  private spinner: HTMLElement | null = null;
  private progressTrack: HTMLElement | null = null;
  private progressFill: HTMLElement | null = null;
  private phaseText: HTMLElement | null = null;
  private indeterminate = true;

  mount(container: HTMLElement): void {
    this.container = container;

    const root = document.createElement("div");
    root.className = "ld-root";
    this.root = root;

    // Spinner
    const spinner = document.createElement("div");
    spinner.className = "ld-spinner";
    this.spinner = spinner;
    root.appendChild(spinner);

    // Progress bar
    const track = document.createElement("div");
    track.className = "ld-progress-track";
    const fill = document.createElement("div");
    fill.className = "ld-progress-fill ld-indeterminate";
    track.appendChild(fill);
    this.progressTrack = track;
    this.progressFill = fill;
    root.appendChild(track);

    // Phase text
    const phase = document.createElement("div");
    phase.className = "ld-phase";
    phase.textContent = "Loading\u2026";
    this.phaseText = phase;
    root.appendChild(phase);

    container.appendChild(root);
  }

  setProgress(percent: number, phase?: string): void {
    this.indeterminate = false;
    if (this.progressFill) {
      this.progressFill.classList.remove("ld-indeterminate");
      this.progressFill.style.width = `${Math.max(0, Math.min(100, percent))}%`;
    }
    if (this.spinner) {
      this.spinner.style.display = "none";
    }
    if (phase && this.phaseText) {
      this.phaseText.textContent = phase;
    }
  }

  setIndeterminate(phase?: string): void {
    this.indeterminate = true;
    if (this.progressFill) {
      this.progressFill.classList.add("ld-indeterminate");
      this.progressFill.style.width = "";
    }
    if (this.spinner) {
      this.spinner.style.display = "";
    }
    if (phase && this.phaseText) {
      this.phaseText.textContent = phase;
    }
  }

  destroy(): void {
    if (this.root && this.container) {
      this.container.removeChild(this.root);
    }
    this.root = null;
    this.container = null;
    this.spinner = null;
    this.progressTrack = null;
    this.progressFill = null;
    this.phaseText = null;
  }
}
