export interface PresetStage {
  key: string;
  scanner: string;
  classification: string;
  label: string;
}

export interface PresetRate {
  packets_per_second: number;
  concurrency: number;
}

export interface Preset {
  key: string;
  version: number;
  name: string;
  use_case: string;
  description: string;
  stages: PresetStage[];
  rate: PresetRate;
  workload_class: string;
  duration_class: string;
  mode: string;
  web_profile: string | null;
  intrusive: boolean;
  active_web: boolean;
  uses_credentials: boolean;
}

export interface SkippedStage {
  stage: string;
  scanner: string;
  reason: string;
}

export interface ScannerStatus {
  scanner: string;
  status: string;
  detail: string;
}

export interface PresetPreview {
  preset: string;
  preset_version: number;
  stages_to_run: PresetStage[];
  skipped: SkippedStage[];
  blocked: boolean;
  estimate: Record<string, string>;
  tuning: PresetRate;
  scanners: ScannerStatus[];
}
