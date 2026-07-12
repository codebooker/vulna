import { hashFor } from '../lib/nav';
import { PageHeader } from '../components/app/page-header';
import { OnboardingWizard } from './OnboardingWizard';

/** Getting started: hosts the guided first-run wizard on its own page so the
 *  Overview stays a dashboard. */
export function GettingStartedPage() {
  // When setup finishes (or is skipped) leave the wizard for the dashboard and
  // reload so the app re-reads onboarding state — otherwise a plain reload keeps
  // the #getting-started hash and lands right back on the wizard, which reads as
  // "Finish setup does nothing".
  const finish = () => {
    window.location.hash = hashFor('overview');
    window.location.reload();
  };
  return (
    <div aria-label="Getting started">
      <PageHeader
        crumbs={[{ label: 'Administration' }, { label: 'Getting started' }]}
        title="Getting started"
        description="A short setup that gets you from here to a safe first assessment. Nothing is scanned until you explicitly approve a target range."
      />
      <div className="mx-auto max-w-3xl">
        <OnboardingWizard onFinished={finish} />
      </div>
    </div>
  );
}
