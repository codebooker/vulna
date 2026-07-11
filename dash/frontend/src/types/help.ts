export interface HelpTopic {
  key: string;
  title: string;
  summary: string;
  doc: string;
}

export interface DemoStatus {
  demo_mode: boolean;
  seeded: boolean;
  created?: boolean;
}
