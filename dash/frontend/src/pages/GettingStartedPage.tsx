import { PageHeader } from '../components/app/page-header';
import { OnboardingWizard } from './OnboardingWizard';

/** Getting started: hosts the guided first-run wizard on its own page so the
 *  Overview stays a dashboard. The wizard itself is unchanged. */
export function GettingStartedPage() {
  return (
    <div aria-label="Getting started">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Getting started' }]}
        title="Getting started"
        description="A short setup that gets you from here to a safe first assessment. Nothing is scanned until you explicitly approve a target range."
      />
      <div className="mx-auto max-w-3xl">
        <OnboardingWizard onFinished={() => window.location.reload()} />
      </div>
    </div>
  );
}
