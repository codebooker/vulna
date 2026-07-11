export interface MaintenanceItem {
  domain: string;
  state: 'ok' | 'warn' | 'action';
  summary: string;
  detail: string;
  action: string;
  doc: string;
}

export interface MaintenanceOverview {
  overall_state: 'ok' | 'warn' | 'action';
  summary: Record<string, number>;
  items: MaintenanceItem[];
}

export interface StorageCategory {
  category: string;
  bytes: number;
  location: string;
  note?: string;
}

export interface StorageBudgets {
  categories: StorageCategory[];
  disk: { free_pct: number; total_bytes: number; free_bytes?: number };
}

export interface CleanupItem {
  kind: string;
  id: string;
  size_bytes: number;
  created_at: string;
  reason: string;
}

export interface CleanupPreview {
  policy: Record<string, number>;
  generated_at: string;
  reclaimable_bytes: number;
  eligible: CleanupItem[];
  protected: CleanupItem[];
}
