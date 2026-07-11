export interface BackupCenter {
  default_destination: string;
  destinations: string[];
  retention_days: number;
  contents: string[];
  encryption: string;
  how_to_create: string;
  how_to_verify: string;
  how_to_restore: string;
  warning: string;
}
