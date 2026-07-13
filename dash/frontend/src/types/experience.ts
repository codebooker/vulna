export type ExperienceProfile = 'small_business' | 'enterprise' | 'custom';

export interface CapabilityStatus {
  key: string;
  name: string;
  status: 'available' | 'planned';
  production_ready: boolean;
}

export interface ExperienceChange {
  experience_profile: ExperienceProfile;
  feature_overrides: Record<string, boolean>;
}

export interface Experience extends ExperienceChange {
  route_visibility: Record<string, boolean>;
  core_routes: string[];
  advanced_routes: string[];
  capabilities: CapabilityStatus[];
  note: string;
}

export interface ExperiencePreview extends Experience {
  changed_routes: string[];
}
