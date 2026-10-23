export const THEME_SYNTHESIS_PHASES = [
  'load_snapshot',
  'load_index',
  'decrypt',
  'embed',
  'tag',
  'name',
  'relate',
  'classify',
  'aggregate',
  'persist',
] as const;

export type ThemeSynthesisPhase = (typeof THEME_SYNTHESIS_PHASES)[number];

export interface ThemePhaseProbe {
  enter(phase: ThemeSynthesisPhase): void;
}

export const NO_PHASE_PROBE: ThemePhaseProbe = { enter: () => undefined };

export class ThemePhaseTracker implements ThemePhaseProbe {
  private phase: ThemeSynthesisPhase | undefined;

  enter(phase: ThemeSynthesisPhase): void {
    this.phase = phase;
  }

  get current(): ThemeSynthesisPhase | undefined {
    return this.phase;
  }
}

export function themeDeadlineCode(phase: ThemeSynthesisPhase): string {
  return `synthesis_theme_deadline_${phase}`;
}
